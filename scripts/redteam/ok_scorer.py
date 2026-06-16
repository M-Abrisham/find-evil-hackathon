#!/usr/bin/env python3
import argparse, re

def score(found, gold):
    return len(set(found) & set(gold)) / max(len(gold), 1)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--found")
    print(score([], []))
