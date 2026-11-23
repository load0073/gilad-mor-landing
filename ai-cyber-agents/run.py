"""CLI: python run.py [--days 14] [--out reports]"""
import argparse
import datetime as dt
import logging
import os

from agents.orchestrator import Orchestrator
from agents.report import write_all


def main():
    p = argparse.ArgumentParser(description="AI cyber findings scan (Opus manager + Haiku/Sonnet workers)")
    p.add_argument("--days", type=int, default=14, help="look-back window in days")
    p.add_argument("--out", default="reports", help="output directory")
    p.add_argument("--domain", action="append", help="override focus areas (repeatable)")
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

    until = dt.date.today()
    since = until - dt.timedelta(days=a.days)
    report = Orchestrator(since.isoformat(), until.isoformat(), a.domain).run()
    os.makedirs(a.out, exist_ok=True)
    for path in write_all(report, os.path.join(a.out, f"ai-cyber-report-{until.isoformat()}")):
        print("wrote", path)


if __name__ == "__main__":
    main()
