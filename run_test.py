#!/usr/bin/env python
# Simple test script to verify the application runs correctly

from aquaguard import create_app

if __name__ == "__main__":
    app = create_app()
    print("Application initialized successfully!")
    print("All imports are working correctly.")