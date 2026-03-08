"""ASCII art banner and branding for Aquiles."""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from aquiles import __version__

BANNER_ART = r'''
      ___        ____    __  __   ___   _       ______   _____
     /   |      / __ \  / / / /  /  _/ / /      / ____/  / ___/
    / /| |     / / / / / / / /   / /  / /      / __/     \__ \ 
   / ___ |    / /_/ / / /_/ /  _/ /  / /___   / /___    ___/ / 
  /_/  |_|    \___\_\ \____/  /___/ /_____/  /_____/   /____/  
                      
                     .ed"""" """$$$$be.
                   -"           ^""**$$$e.
                 ."                   '$$$c
                /                      "4$$b
               d  3                      $$$$
               $  *                   .$$$$$$
              .$  ^c           $$$$$e$$$$$$$$.
              d$L  4.         4$$$$$$$$$$$$$$b
              $$$$b ^ceeeee.  4$$ECL.F*$$$$$$$
  e$""=.      $$$$P d$$$$F $ $$$$$$$$$- $$$$$$
 z$$b. ^c     3$$$F "$$$$b   $"$$$$$$$  $$$$*"      .=""$c
4$$$$L        $$P"  "$$b   .$ $$$$$...e$$        .=  e$$$.
^*$$$$$c  %..   *c    ..    $$ 3$$$$$$$$$$eF     zP  d$$$$$
  "**$$$ec   "   %ce""    $$$  $$$$$$$$$$*    .r" =$$$$P""
        "*$b.  "c  *$e.    *** d$$$$$"L$$    .d"  e$$***"
          ^*$$c ^$c $$$      4J$$$$$% $$$ .e*".eeP"
             "$$$$$$"'$=e....$*$$**$cz$$" "..d$*"
               "*$$$  *=%4.$ L L$ P3$$$F $$$P"
                  "$   "%*ebJLzb$e$$$$$b $P"
                    %..      4$$$$$$$$$$ "
                     $$$e   z$$$$$$$$$$%
                      "*$c  "$$$$$$$P"
                       ."""*$$$$$$$$bc
                    .-"    .$***$$$"""*e.
                 .-"    .e$"     "*$c  ***.
          .=*""""    .e$*"          "*bc  "*$e..
        .$"        .z*"               ^*$e.   "*****e.
        $$ee$c   .d"                     "*$.        3.
        ^*$E")$..$"                         *   .ee==d%
           $.d$$$*                           *  J$$$d*
            """""                              "$$$"
'''

SUBTITLE = "[ AI-Assisted Pentesting Orchestrator ]"


def show_banner(console: Console | None = None) -> None:
    """Display the Aquiles startup banner."""
    c = console or Console()

    banner_text = Text(BANNER_ART, style="bold red")
    subtitle_text = Text(SUBTITLE, style="bold yellow", justify="center")
    version_text = Text(f"v{__version__}", style="dim white", justify="center")

    content = Text.assemble(
        banner_text, "\n",
        subtitle_text, "\n",
        version_text,
    )

    panel = Panel(
        content,
        border_style="bright_red",
        padding=(1, 4),
    )
    c.print(panel)
    c.print()
