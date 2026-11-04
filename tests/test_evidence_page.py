"""Static checks for read-only assessment evidence explorer."""
import ast
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_evidence_blocks():
    tree = ast.parse((ROOT / 'dashboard/evidence_page.py').read_text())
    blocks = next(n.value for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'BLOCKS' for t in n.targets))
    assert [e.elts[0].value for e in blocks.elts] == ['1', '2', '3', '4', '5', '9']

def test_requirements_and_pdf():
    text = (ROOT / 'dashboard/evidence_page.py').read_text()
    assert all(x in text for x in ('R1','R2','R3','R4','AI LOG FILE FOR SUS NOT .pdf','st.download_button'))
    assert 'subprocess.run' not in text

def test_wired_to_dashboard():
    text = (ROOT / 'dashboard/app.py').read_text()
    assert 'from dashboard.evidence_page import evidence_page' in text
