#!/usr/bin/env python3
"""
Test Monitoring Tools
====================

Simple test to validate that the monitoring tools can be imported
and basic functionality works before deploying to Pi.
"""

import sys
import importlib.util


def test_import(module_name, file_path):
    """Test if a module can be imported"""
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        print(f"✅ {module_name}: Import successful")
        return True
    except Exception as e:
        print(f"❌ {module_name}: Import failed - {e}")
        return False


def main():
    """Test all monitoring tools"""
    print("🔧 Testing Tesla Radar Monitoring Tools")
    print("=" * 50)
    print("Validating imports and basic functionality...")
    print()

    tools_to_test = [
        ("radar_quick_status", "radar_quick_status.py"),
        ("radar_next_phase_monitor", "radar_next_phase_monitor.py"),
        ("radar_activation_dashboard", "radar_activation_dashboard.py"),
        ("radar_activation_status_monitor", "radar_activation_status_monitor.py"),
        ("tesla_complete_emulator", "tesla_complete_emulator.py"),
        ("tesla_protocol_with_631_monitor", "tesla_protocol_with_631_monitor.py"),
    ]

    passed = 0
    total = len(tools_to_test)

    for module_name, file_path in tools_to_test:
        if test_import(module_name, file_path):
            passed += 1

    print()
    print(f"📊 Test Results: {passed}/{total} tools passed import test")

    if passed == total:
        print("✅ All tools ready for deployment to Pi")
        print()
        print("🎯 NEXT STEPS:")
        print("1. Copy tools to Pi (if not already there)")
        print("2. Ensure Tesla protocol emulator is running")
        print("3. Run radar_quick_status.py for immediate status")
        print("4. Use radar_next_phase_monitor.py for ongoing monitoring")
    else:
        print("❌ Some tools have issues - fix before deploying")

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
