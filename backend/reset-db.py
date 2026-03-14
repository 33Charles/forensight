#!/usr/bin/env python3
"""
Forensight — Database Reset Script
Drops all tables and recreates them fresh.
Run from the backend directory: python3 reset_db.py
"""
import sys
import os

# Confirm before wiping
print("\n⚠  This will DELETE all data in the database.")
confirm = input("   Type 'yes' to continue: ").strip().lower()

if confirm != "yes":
    print("   Aborted.")
    sys.exit(0)

from app import create_app
from database.db import db

app = create_app()
with app.app_context():
    db.drop_all()
    print("   ✓ All tables dropped")
    db.create_all()
    print("   ✓ All tables recreated")
    print("\n   Database reset complete. Run python3 app.py to set up admin.\n")