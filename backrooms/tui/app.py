"""Textual-based TUI dashboard for Backrooms."""

from collections.abc import Iterable

from textual.app import App
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Footer, Header, Static


class DashboardScreen(Screen[None]):
    """Main dashboard showing module status."""

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
    ]

    def compose(self) -> Iterable[Widget]:
        yield Header(show_clock=True)
        yield Vertical(
            Static("[bold yellow]Backrooms[/bold yellow] TUI dashboard"),
            Static("[dim]Interactive modules coming soon...[/dim]"),
            id="dashboard",
        )
        yield Footer()


class BackroomsApp(App[None]):
    """Main Textual application."""

    TITLE = "Backrooms"
    SUB_TITLE = "Red Team Network Toolkit"

    CSS = """
    #dashboard {
        padding: 1 2;
        height: 100%;
    }
    """

    def on_mount(self) -> None:
        self.push_screen(DashboardScreen())


def run_tui() -> None:
    """Install and run the TUI."""
    BackroomsApp().run()


if __name__ == "__main__":
    run_tui()
