#!/usr/bin/env python3
"""
Tesla Radar Activation Entry Point

Main script for activating Tesla radar units to exit plant mode.
Uses the consolidated src/ package structure.

Usage:
    python scripts/activate_radar.py --help
    python scripts/activate_radar.py --vin 5YJSB7E43GF113105 --duration 10
"""
import argparse
import sys
from pathlib import Path

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.protocol.tesla_radar_protocol import TeslaRadarProtocol, setup_can
from src.activation.tesla_radar_activator import TeslaRadarActivator, SCPIPowerController


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tesla Radar Activation Tool - Exit Plant Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic activation with default parameters
    python scripts/activate_radar.py --vin 5YJSB7E43GF113105

    # With custom gateway parameters
    python scripts/activate_radar.py --vin 5YJSB7E43GF113105 --country 826 --awd

    # Dry run (protocol only, no activation sequence)
    python scripts/activate_radar.py --vin 5YJSB7E43GF113105 --dry-run

    # With SCPI power cycling
    python scripts/activate_radar.py --vin 5YJSB7E43GF113105 --scpi-port /dev/cu.usbserial-2210
""",
    )

    # Basic options
    parser.add_argument("--vin", default="5YJSB7E43GF113105", help="Vehicle VIN")
    parser.add_argument("--duration", type=float, default=10.0, help="Activation duration in seconds")
    parser.add_argument("--can-interface", default="can0", help="CAN interface/channel (default: can0 = Radar CAN1)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--dry-run", action="store_true", help="Run protocol without activator sequence")

    # Gateway configuration
    gateway = parser.add_argument_group("Gateway Configuration (0x398)")
    gateway.add_argument("--country", type=int, default=826, help="Country code (826=UK, 840=US, 276=DE)")
    gateway.add_argument("--awd", action="store_true", dest="four_wheel_drive", help="Enable AWD flag")
    gateway.add_argument("--rwd", action="store_false", dest="four_wheel_drive", help="Disable AWD flag")
    gateway.add_argument("--air-suspension", type=int, default=3, help="Air suspension type (0-3)")
    gateway.add_argument("--chassis-type", type=int, default=1, help="Chassis type (0-3)")
    gateway.add_argument("--epas-type", type=int, default=1, help="EPAS type (0-3)")
    gateway.add_argument("--performance-config", type=int, default=2, help="Performance config (0-3)")
    gateway.add_argument("--autopilot", type=int, default=1, help="Autopilot level (0-3)")
    gateway.add_argument("--rhd", type=int, default=1, help="Right-hand drive (0=LHD, 1=RHD)")
    parser.set_defaults(four_wheel_drive=True)

    # Radar configuration
    radar = parser.add_argument_group("Radar Configuration (0x2A9)")
    radar.add_argument("--radar-position", type=int, default=0, help="Radar position (0-2)")
    radar.add_argument("--radar-epas-type", type=int, default=0, help="Radar EPAS type (0-1)")

    # SCPI power control
    scpi = parser.add_argument_group("SCPI Power Control")
    scpi.add_argument("--scpi-port", help="SCPI serial port for power cycling")
    scpi.add_argument("--scpi-off-time", type=float, default=1.5, help="Power off duration (seconds)")
    scpi.add_argument("--scpi-wait", type=float, default=3.0, help="Wait after power on (seconds)")
    scpi.add_argument("--no-scpi", action="store_true", help="Disable SCPI power cycling")

    # Output options
    output = parser.add_argument_group("Output")
    output.add_argument("--run-log", type=Path, help="Path to run history log")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    print("=" * 60)
    print("Tesla Radar Activation Tool")
    print("=" * 60)
    print(f"VIN: {args.vin}")
    print(f"Duration: {args.duration}s")
    print(f"Country: {args.country}")
    print(f"AWD: {args.four_wheel_drive}")
    print("=" * 60)

    # Setup CAN interface
    try:
        bus = setup_can(interface=args.can_interface)
    except Exception as e:
        print(f"Failed to setup CAN interface: {e}")
        return 1

    try:
        # Setup power controller if requested
        power_controller = None
        if args.scpi_port and not args.no_scpi:
            power_controller = SCPIPowerController(
                args.scpi_port,
                off_time=args.scpi_off_time,
                wait_before_activation=args.scpi_wait,
            )

        if args.dry_run:
            # Just run the protocol directly
            protocol = TeslaRadarProtocol(
                bus,
                vin=args.vin,
                debug=args.debug,
                performance_config=args.performance_config,
                air_suspension=args.air_suspension,
                chassis_type=args.chassis_type,
                four_wheel_drive=args.four_wheel_drive,
                autopilot_level=args.autopilot,
            )
            protocol.radarPosition = args.radar_position
            protocol.radarEpasType = args.radar_epas_type
            protocol.gateway_country = args.country
            protocol.gateway_rhd = args.rhd
            protocol.gateway_epas_type = args.epas_type

            print("Starting protocol (dry-run mode)...")
            print("Press Ctrl+C to stop")
            protocol.start()

        else:
            # Use the full activator
            activator = TeslaRadarActivator(
                bus,
                vin=args.vin,
                debug=args.debug,
                power_controller=power_controller,
                run_log_path=str(args.run_log) if args.run_log else None,
                performance_config=args.performance_config,
                air_suspension=args.air_suspension,
                chassis_type=args.chassis_type,
                four_wheel_drive=args.four_wheel_drive,
                autopilot_level=args.autopilot,
            )

            # Apply additional configuration
            proto = activator.protocol
            proto.radarPosition = args.radar_position
            proto.radarEpasType = args.radar_epas_type
            proto.gateway_country = args.country
            proto.gateway_rhd = args.rhd
            proto.gateway_epas_type = args.epas_type

            print("Starting activation sequence...")
            record = activator.run_activation_sequence(
                duration=int(args.duration),
                metadata={"source": "activate_radar.py"},
            )

            # Show results
            print("\n" + "=" * 60)
            print("Results")
            print("=" * 60)
            print(f"VIN Complete: {record.get('vin_complete')}/7")
            print(f"Init Messages (0x631): {record.get('init_messages', 0)}")
            print(f"Status Messages (0x300): {record.get('status_messages', 0)}")

            error_codes = record.get("error_base_codes_hex", [])
            error_names = record.get("error_base_codes_names", {})
            if error_codes:
                print("Error Codes:")
                for code in error_codes:
                    name = error_names.get(code, "UNKNOWN")
                    print(f"  - {code}: {name}")
            else:
                print("Error Codes: None (success!)")

            activator.protocol.stop()

    except KeyboardInterrupt:
        print("\nStopped by user")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        bus.shutdown()
        print("CAN interface closed")

    return 0


if __name__ == "__main__":
    sys.exit(main())
