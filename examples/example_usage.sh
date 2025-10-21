#!/bin/sh
#
# Example usage script for isolate with capability detection
#

set -e

ISOLATE_BIN="./bin/isolate"
EXAMPLE_APP="./examples/server"

echo "Isolate Integration Demo"
echo "========================"
echo

# Check if isolate is built
if [ ! -f "$ISOLATE_BIN" ]; then
    echo "Building isolate..."
    make all
    echo
fi

# Check if example app exists
if [ ! -f "$EXAMPLE_APP" ]; then
    echo "Building example applications..."
    make examples
    echo
fi

echo "Step 1: Detect capabilities for the example server"
echo "---------------------------------------------------"
$ISOLATE_BIN -d $EXAMPLE_APP
echo

echo "Step 2: Show generated capability file"
echo "--------------------------------------"
echo "Generated file: ${EXAMPLE_APP}.caps"
echo
cat "${EXAMPLE_APP}.caps"
echo

echo "Step 3: Run the application with detected capabilities"
echo "------------------------------------------------------"
echo "Note: This requires root privileges (use doas/sudo)"
echo "Command: doas $ISOLATE_BIN -v $EXAMPLE_APP"
echo

read -p "Run the isolated server? (y/N): " answer
case $answer in
    [Yy]*)
        echo "Starting isolated server..."
        echo "Press Ctrl+C to stop"
        echo
        doas $ISOLATE_BIN -v $EXAMPLE_APP
        ;;
    *)
        echo "Skipping execution."
        ;;
esac

echo
echo "Demo completed!"
echo
echo "Usage Summary:"
echo "  # Detect capabilities:"
echo "  $ISOLATE_BIN -d /path/to/binary"
echo
echo "  # Run with isolation:"
echo "  doas $ISOLATE_BIN /path/to/binary [args...]"
echo
echo "  # Run with custom capability file:"
echo "  doas $ISOLATE_BIN -c custom.caps /path/to/binary"
echo
echo "  # Dry run (test without execution):"
echo "  $ISOLATE_BIN -n /path/to/binary"
