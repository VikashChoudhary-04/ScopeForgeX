import sys
from scopeforgex.cli import main
from scopeforgex.installer import install_tools

if __name__ == "__main__":
    if "--install-tools" in sys.argv:
        install_tools()
    else:
        main()
