import io
import json
import zipfile

import cv2
import numpy as np
import pytest
from PIL import Image
from PIL.PngImagePlugin import PngInfo

from app import db
from app.schemas import RiskQuestionnaire
from app.services import alerts, detector, evidence, forensics, hashing, metadata, registry, reporting, risk
from app.services.imaging import ImageError, load_image

rng = np.random.default_rng(7)


def scene(size=(480, 640), seed=1) -> np.ndarray:
    """Synthetic textured picture (random shapes + noise) good enough for hashing/ORB tests."""
    r = np.random.default_rng(seed)
    img = np.full((*size, 3), 120, np.uint8)
    for _ in range(120):
        c = tuple(int(x) for x in r.integers(0, 255, 3))
        p = (int(r.integers(0, size[1])), int(r.integers(0, size[0])))
        if r.random() < 0.5:
            cv2.circle(img, p, int(r.integers(5, 40)), c, -1)
        else:
            cv2.rectangle(img, p, (p[0] + int(r.integers(10, 60)), p[1] + int(r.integers(10, 60))), c, -1)
    img = cv2.add(img, r.integers(0, 12, img.shape, dtype=np.uint8))
    return img


def to_bytes(arr: np.ndarray, fmt="JPEG", **kw) -> bytes:
    b = io.BytesIO()
    Image.fromarray(arr).save(b, fmt, **kw)
    return b.getvalue()


# ------------------------------------------------------------ hashing
def test_perceptual_hash_survives_resize_and_recompress():
    a = scene()
    orig = Image.fromarray(a)
    small = Image.open(io.BytesIO(to_bytes(cv2.resize(a, (320, 240)), quality=60)))
    other = Image.fromarray(scene(seed=99))
    assert hashing.hamming(hashing.phash(orig), hashing.phash(small)) <= 8
    assert hashing.hamming(hashing.phash(orig), hashing.phash(other)) > 14


def test_registry_flags_derivative():
    owner = "tester"
    raw = to_bytes(scene())
    img, _ = load_image(raw)
    registry.register(owner, "my selfie", hashing.fingerprints(img, raw))
    edited = to_bytes(cv2.GaussianBlur(scene(), (5, 5), 0), quality=70)
    eimg, _ = load_image(edited)
    hits = registry.find_matches(owner, hashing.fingerprints(eimg, edited))
    assert hits and hits[0]["label"] == "my selfie" and not hits[0]["identical_file"]
    assert registry.find_matches("someone-else", hashing.fingerprints(eimg, edited)) == []


# ------------------------------------------------------------ metadata
def test_png_ai_chunk_and_xmp_detected():
    info = PngInfo()
    info.add_text("parameters", "a cat, Steps: 20, Sampler: Euler a, CFG scale: 7")
    info.add_text("XML:com.adobe.xmp", "<x:xmpmeta>http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia</x:xmpmeta>")
    b = io.BytesIO()
    Image.fromarray(scene()).save(b, "PNG", pnginfo=info)
    codes = {s["code"] for s in metadata.extract_metadata(b.getvalue())["ai_signatures"]}
    assert {"png_ai_chunk", "iptc_ai_generated", "sd_parameters"} <= codes


def _jpeg_with_gps() -> bytes:
    exif = Image.Exif()
    exif[0x010F] = "TestCam"
    exif[0x0110] = "X1"
    exif[0x0131] = "Adobe Photoshop 25"
    gps = exif.get_ifd(0x8825)
    gps.update({1: "N", 2: (12.0, 58.0, 30.0), 3: "E", 4: (77.0, 35.0, 0.0)})
    exif[0x8825] = gps
    b = io.BytesIO()
    Image.fromarray(scene()).save(b, "JPEG", exif=exif)
    return b.getvalue()


def test_gps_detected_rounded_then_scrubbed():
    data = _jpeg_with_gps()
    m = metadata.extract_metadata(data)
    assert m["gps_present"]
    assert abs(m["gps_approx"]["lat"] - 12.975) <= 0.006 and abs(m["gps_approx"]["lon"] - 77.583) <= 0.006
    assert len(str(m["gps_approx"]["lat"]).split(".")[1]) <= 2  # rounded, not exact
    assert m["camera"] == "TestCam X1" and "edited_with_photo_editor" in m["flags"]
    img, fmt = load_image(data)
    clean, mime = alerts.scrub_metadata(img, fmt)
    m2 = metadata.extract_metadata(clean)
    assert not m2["gps_present"] and not m2["has_exif"] and mime == "image/jpeg"


# ------------------------------------------------------------ forensics / detector
def test_copy_move_detects_cloned_region():
    a = scene()
    clean = forensics.copy_move(cv2.cvtColor(a, cv2.COLOR_RGB2GRAY).astype(np.float32))
    b = a.copy()
    b[300:420, 400:520] = a[40:160, 60:180]
    cloned = forensics.copy_move(cv2.cvtColor(b, cv2.COLOR_RGB2GRAY).astype(np.float32))
    assert cloned["score"] > clean["score"] and cloned["consistent_matches"] >= 8


def test_declared_ai_image_gets_high_verdict_and_limitations():
    info = PngInfo()
    info.add_text("parameters", "Steps: 30, Sampler: DPM++")
    b = io.BytesIO()
    Image.fromarray(scene()).save(b, "PNG", pnginfo=info)
    r = detector.analyze_image(b.getvalue(), include_heatmap=True)
    assert r["verdict"] == "likely_ai_or_manipulated" and r["confidence"] == "high"
    assert r["ela_heatmap_png_b64"] and r["limitations"]


def test_plain_image_never_gets_high_confidence_from_heuristics_alone():
    r = detector.analyze_image(to_bytes(scene()))
    assert r["confidence"] == "low" and r["ai_generated_likelihood"] <= 0.55


@pytest.mark.parametrize("bad", [b"", b"not an image", b"\x89PNG\r\n\x1a\n" + b"0" * 20])
def test_invalid_uploads_rejected(bad):
    with pytest.raises(ImageError):
        load_image(bad)


def test_unsupported_format_rejected():
    b = io.BytesIO()
    Image.fromarray(scene()).save(b, "BMP")
    with pytest.raises(ImageError) as e:
        load_image(b.getvalue())
    assert e.value.status == 415


# ------------------------------------------------------------ evidence vault
def test_evidence_chain_export_and_tamper_detection():
    owner = "owner-a"
    case = evidence.create_case(owner, "Fake photo on Insta", "instagram", "ai_generated_or_edited", False)
    d1, d2 = to_bytes(scene(seed=3)), to_bytes(scene(seed=4))
    e1 = evidence.add_evidence(owner, case["id"], d1, mime="image/jpeg", source_url="https://example.com/p/1", note="first")
    e2 = evidence.add_evidence(owner, case["id"], d2, mime="image/jpeg", analysis={"verdict": "possibly_manipulated"})
    assert e2["prev_hash"] == e1["entry_hash"] and e1["sha256"] == hashing.sha256_hex(d1)
    assert evidence.verify_chain(owner, case["id"])["ok"]

    z = zipfile.ZipFile(io.BytesIO(evidence.export_zip(owner, case["id"])))
    names = z.namelist()
    assert "manifest.json" in names and "chain_of_custody.txt" in names and any(n.startswith("files/") for n in names)
    assert json.loads(z.read("manifest.json"))["integrity_check"]["ok"]

    # other users can't see the case
    with pytest.raises(evidence.EvidenceError):
        evidence.list_evidence("owner-b", case["id"])

    # tamper with a note -> chain breaks
    with db.tx() as c:
        c.execute("UPDATE evidence SET note='edited later' WHERE id=?", (e1["id"],))
    res = evidence.verify_chain(owner, case["id"])
    assert not res["ok"] and any("altered" in i for i in res["issues"])


def test_stored_file_tampering_detected():
    owner = "owner-c"
    case = evidence.create_case(owner, "t", None, None, False)
    evidence.add_evidence(owner, case["id"], to_bytes(scene()), mime="image/jpeg")
    row = db.query("SELECT stored_name FROM evidence WHERE case_id=?", (case["id"],))[0]
    from app import config
    p = config.VAULT_DIR / owner / case["id"] / row["stored_name"]
    p.write_bytes(evidence._fernet().encrypt(b"swapped"))
    assert any("does not match" in i for i in evidence.verify_chain(owner, case["id"])["issues"])


def test_minor_sensitive_content_is_never_stored():
    owner = "owner-d"
    case = evidence.create_case(owner, "minor case", "snapchat", "intimate_or_sexual", True)
    e = evidence.add_evidence(owner, case["id"], to_bytes(scene()), kind="intimate_image", note="url only")
    assert e["file_stored"] is False and e["sha256"] is None


# ------------------------------------------------------------ risk + reporting
def test_risk_scoring_and_levels():
    low = risk.assess(RiskQuestionnaire())
    high = risk.assess(RiskQuestionnaire(profile_public=True, posts_face_photos=True, has_found_edited_copy=True,
                                         conflict_with_person_holding_images=True))
    assert low["level"] == "low" and high["level"] in ("high", "critical") and high["recommendations"]


def test_reporting_guide_minor_flow_and_country():
    g = reporting.guide("snapchat", "IN", "intimate_or_sexual", is_minor=True)
    titles = [s["title"] for s in g["steps"]]
    assert any("Do NOT save" in t for t in titles)
    assert any("1930" in str(s["links"]) for s in g["steps"])
    adult = reporting.guide("instagram", "US", "intimate_or_sexual", False)
    assert any("stopncii" in str(s["links"]) for s in adult["steps"])


# ------------------------------------------------------------ watermark
def _photo(seed=1) -> Image.Image:
    a = cv2.GaussianBlur(scene((720, 960), seed).astype(np.float32), (0, 0), 2.0)
    a = a + np.linspace(0, 60, 960, dtype=np.float32)[None, :, None]
    return Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))


def _jpeg(img: Image.Image, q: int) -> Image.Image:
    b = io.BytesIO()
    img.save(b, "JPEG", quality=q)
    return Image.open(io.BytesIO(b.getvalue())).convert("RGB")


def test_watermark_invisible_and_robust():
    from app.services import watermark as wm
    key, img = b"secret", _photo()
    wid = wm.new_id()
    marked = wm.embed(img, wid, key)
    mse = float(((np.asarray(img, float) - np.asarray(marked, float)) ** 2).mean())
    assert 10 * np.log10(255 ** 2 / mse) > 38                                   # visually invisible
    assert wm.detect(marked, key, full_search=False)["wm_id"] == wid
    assert wm.detect(_jpeg(marked, 70), key, full_search=False)["wm_id"] == wid  # recompression
    assert wm.detect(marked.crop((13, 7, 940, 700)), key)["wm_id"] == wid        # crop -> offset search
    patched = np.asarray(marked).copy()
    patched[100:500, 100:600] = np.asarray(_photo(5))[100:500, 100:600]          # ~35% replaced (face-swap-like)
    assert wm.detect(Image.fromarray(patched), key, full_search=False)["wm_id"] == wid


def test_watermark_no_false_positives_and_key_secrecy():
    from app.services import watermark as wm
    key, img = b"secret", _photo()
    marked = wm.embed(img, wm.new_id(), key)
    assert not wm.detect(img, key)["found"]
    assert not wm.detect(_jpeg(img, 75), key)["found"]
    assert not wm.detect(marked, b"wrong-key", full_search=False)["found"]
    with pytest.raises(wm.WatermarkError):
        wm.embed(Image.new("RGB", (64, 64)), wm.new_id(), key)


def test_watermark_scoping_in_pipeline():
    from app.services import pipeline, watermark as wm
    from app import config
    wid = wm.new_id()
    registry.register_watermark("wm-owner", "holiday pic", wid)
    marked = wm.embed(_photo(), wid, config.WM_KEY)
    b = io.BytesIO()
    marked.save(b, "PNG")
    mine = pipeline.full_analysis("wm-owner", b.getvalue())["watermark"]
    other = pipeline.full_analysis("someone-else", b.getvalue())["watermark"]
    assert mine["registered_to_you"] and mine["label"] == "holiday pic"
    assert other["found"] and not other["registered_to_you"] and other["wm_id"] is None


# ------------------------------------------------------------ video
def _make_video(path: str, frames=40, fourcc="mp4v"):
    vw = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*fourcc), 20.0, (320, 240))
    if not vw.isOpened():
        return False
    base = scene((240, 320), 11)
    for i in range(frames):
        vw.write(np.roll(base, i * 2, axis=1)[:, :, ::-1])
    vw.release()
    return True


def test_video_analysis_and_rejections(tmp_path):
    from app.services import video
    p = str(tmp_path / "t.mp4")
    if not _make_video(p):
        pytest.skip("OpenCV build cannot encode mp4 here")
    r = video.analyze_video(open(p, "rb").read())
    assert r["video"]["frames_analyzed"] >= 8 and r["confidence"] == "low" and r["limitations"]
    assert r["verdict"] in ("no_strong_indicators", "possibly_manipulated", "likely_ai_or_manipulated")
    with pytest.raises(ImageError) as e:
        video.analyze_video(b"this is not a video at all")
    assert e.value.status == 415
    with pytest.raises(ImageError):
        video.analyze_video(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 64)       # valid magic, undecodable


def test_video_declared_ai_signature_is_high_confidence(tmp_path):
    from app.services import video
    p = str(tmp_path / "t.mp4")
    if not _make_video(p):
        pytest.skip("OpenCV build cannot encode mp4 here")
    data = open(p, "rb").read() + b"<x>digitalsourcetype/trainedAlgorithmicMedia</x>"
    r = video.analyze_video(data)
    assert r["confidence"] == "high" and r["verdict"] == "likely_ai_or_manipulated"
