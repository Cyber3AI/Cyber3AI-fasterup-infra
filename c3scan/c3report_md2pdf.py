# -*- coding: utf-8 -*-
"""CYBER3 Scan — randare MD → PDF (temă navy, DejaVu pt diacritice RO). Rulează pe portal (reportlab).
Uz: python3 c3report_md2pdf.py raport.md raport.pdf
Suportă: titluri (#/##/###), tabele markdown (clamp coloane min 13mm), liste, **bold**, `cod`, citate, ---."""
import sys, re, os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, Image
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT

pdfmetrics.registerFont(TTFont("DejaVu", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"))
pdfmetrics.registerFont(TTFont("DejaVu-Bold", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"))
pdfmetrics.registerFont(TTFont("DejaVu-Mono", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"))
NAVY = colors.HexColor("#0B2E63"); RED = colors.HexColor("#C0102A"); LIGHT = colors.HexColor("#EAF0F8"); GREY = colors.HexColor("#5A6B82")

def esc(t):
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"`(.+?)`", r'<font face="DejaVu-Mono" size="8">\1</font>', t)
    return t

H1 = ParagraphStyle("H1", fontName="DejaVu-Bold", fontSize=16, textColor=NAVY, spaceAfter=8, spaceBefore=6, leading=20)
H2 = ParagraphStyle("H2", fontName="DejaVu-Bold", fontSize=12.5, textColor=NAVY, spaceAfter=6, spaceBefore=11, leading=15)
H3 = ParagraphStyle("H3", fontName="DejaVu-Bold", fontSize=10.5, textColor=RED, spaceAfter=4, spaceBefore=7, leading=13)
BODY = ParagraphStyle("BODY", fontName="DejaVu", fontSize=9, spaceAfter=5, leading=12.5, alignment=TA_LEFT)
CELL = ParagraphStyle("CELL", fontName="DejaVu", fontSize=7.3, leading=9)
CELLH = ParagraphStyle("CELLH", fontName="DejaVu-Bold", fontSize=7.5, leading=9, textColor=colors.white)
BUL = ParagraphStyle("BUL", fontName="DejaVu", fontSize=9, leading=12.5, leftIndent=12, spaceAfter=2)

def build(md, out, logo=None):
    st = []
    if logo and os.path.exists(logo):
        try:
            iw, ih = ImageReader(logo).getSize(); w = 26 * mm; h = w * ih / iw
            st.append(Image(logo, width=w, height=h)); st.append(Spacer(1, 4))
        except Exception:
            pass
    lines = md.split("\n"); i = 0
    while i < len(lines):
        ln = lines[i].rstrip()
        if not ln.strip(): st.append(Spacer(1, 3)); i += 1; continue
        if ln.startswith("# "): st.append(Paragraph(esc(ln[2:]), H1)); st.append(HRFlowable(width="100%", thickness=1.4, color=NAVY, spaceAfter=6))
        elif ln.startswith("## "): st.append(Paragraph(esc(ln[3:]), H2))
        elif ln.startswith("### "): st.append(Paragraph(esc(ln[4:]), H3))
        elif ln.startswith("---"): st.append(HRFlowable(width="100%", thickness=0.6, color=GREY, spaceBefore=4, spaceAfter=4))
        elif ln.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                r = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not re.match(r"^[\s:\-]+$", "".join(r)): rows.append(r)
                i += 1
            if rows:
                nc = max(len(r) for r in rows)
                data = [[Paragraph(esc(c), CELLH if ri == 0 else CELL) for c in (r + [""] * (nc - len(r)))] for ri, r in enumerate(rows)]
                t = Table(data, colWidths=[max(13 * mm, 174 * mm / nc)] * nc, repeatRows=1)
                t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C3CEDF")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
                st.append(t); st.append(Spacer(1, 6)); continue
        elif ln.startswith(("- ", "* ")): st.append(Paragraph("• " + esc(ln[2:]), BUL))
        elif re.match(r"^\d+\.\s", ln): st.append(Paragraph(esc(ln), BUL))
        elif ln.startswith("> "): st.append(Paragraph(esc(ln[2:]), ParagraphStyle("Q", parent=BODY, leftIndent=10, textColor=GREY, fontSize=8.6)))
        else: st.append(Paragraph(esc(ln), BODY))
        i += 1
    SimpleDocTemplate(out, pagesize=A4, topMargin=15 * mm, bottomMargin=15 * mm, leftMargin=18 * mm, rightMargin=18 * mm, title="CYBER3 Scan").build(st)

if __name__ == "__main__":
    build(open(sys.argv[1], encoding="utf-8").read(), sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    print("PDF", sys.argv[2].split("/")[-1])
