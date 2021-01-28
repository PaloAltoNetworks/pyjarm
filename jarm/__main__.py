try:
    from jarm.cli import run
except ImportError:
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from jarm.cli import run

if __name__ == "__main__":
    run()
