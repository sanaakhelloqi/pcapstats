from pathlib import Path
from typing import List

from PyPDF2 import PdfFileMerger, PdfFileReader


def merge_pdfs(pdf_list: List[str], delete_originals=True, out="result.pdf"):
    merger = PdfFileMerger()

    for item in pdf_list:
        for pdf in item:
            merger.append(PdfFileReader(pdf))

    merger.write(out)
    merger.close()

    # Löscht alle PDFs in Liste pdf_output
    for item in pdf_list:
        for pdf in map(Path, item):
            pdf.unlink()


def get_basename(path: Path) -> str:
    return path.name.split(".")[0]
