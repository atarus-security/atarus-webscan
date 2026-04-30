"""PDF report generation via WeasyPrint"""
import os
from weasyprint import HTML
from atarus_webscan.reports import html as html_report
from atarus_webscan.models import ScanResult
from atarus_webscan.scope import ScopeValidator


def generate(result: ScanResult, output_dir: str, existing_html_path: str = None) -> str:
    os.makedirs(output_dir, exist_ok=True)

    if existing_html_path and os.path.exists(existing_html_path):
        html_path = existing_html_path
    else:
        html_path = html_report.generate(result, output_dir)

    with open(html_path, "r") as f:
        html_content = f.read()

    pdf_css = """
    <style>
      @page {
        size: A4;
        margin: 18mm 14mm;
        @bottom-center {
          content: "Atarus Offensive Security | Confidential";
          font-size: 9px;
          color: #555;
        }
        @bottom-right {
          content: "Page " counter(page) " of " counter(pages);
          font-size: 9px;
          color: #555;
        }
      }
      body { background: #060606 !important; }
      .finding { page-break-inside: avoid; }
      .stat-card { page-break-inside: avoid; }
      .tech-card { page-break-inside: avoid; }
    </style>
    """
    html_content = html_content.replace("</head>", pdf_css + "</head>")

    safe_target = ScopeValidator.sanitize_filename(result.target)
    pdf_path = os.path.join(output_dir, f"atarus-webscan-{safe_target}.pdf")

    HTML(string=html_content, base_url=output_dir).write_pdf(pdf_path)

    return pdf_path
