from .models import ReportData


class ReportGenerator:
    """
    Base report generator.

    This class converts a populated ReportData object into
    one or more report formats.

    Current:
        Markdown

    Future:
        JSON
        HTML
        PDF
    """

    def __init__(self, report: ReportData):
        self.report = report

    def generate_markdown(self, output_file: str) -> None:
        """
        Placeholder implementation.

        The full Markdown renderer will be implemented
        in the next step of the reporting engine.
        """
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# ScopeForgeX Report\n\n")
            f.write("Professional Reporting Engine\n\n")
            f.write("This report generator is under construction.\n")
