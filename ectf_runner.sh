#!/bin/bash
# Simple ECTF Build, Flash, Subscribe, and Test Wrapper Script
# This script activates the Python virtual environment and then:
#   - builds the decoder (using internal config values)
#   - flashes the built firmware to a board (requires port argument)
#   - for each provided channel, deletes any existing subscription file in the "subscriptions" folder,
#     generates a new subscription binary, and applies it to the board.
#   - runs tests based on a test type (encode, decode, or regular)
#
# Usage examples:
#   ./ectf_runner.sh build
#   ./ectf_runner.sh flash /dev/ttyACM0
#   ./ectf_runner.sh subscribe /dev/ttyACM0 1 2 3
#   ./ectf_runner.sh test encode
#   ./ectf_runner.sh test decode /dev/ttyACM0 1 2 3
#   ./ectf_runner.sh test regular /dev/ttyACM0 64 1 2 4

# Activate the Python virtual environment.
if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
else
  echo "Error: Virtual environment (.venv) not found. Please create it first."
  exit 1
fi

# Configuration values.
DEFAULT_GLOBAL_SECRETS="global.secrets"
DEFAULT_DECODER_ID="0xdeadbeef"
DEFAULT_BUILD_OUT_DIR="deadbeef_build"
DEFAULT_STRESS_TEST_JSON="test.json"

# Ensure a subcommand is provided.
if [ $# -lt 1 ]; then
  echo "Usage: $0 {build|flash|subscribe|test} [arguments...]"
  exit 1
fi

CMD="$1"
shift

case "$CMD" in
build)
  echo -e "\n\033[1mBuilding decoder...\033[0m\n"
  docker build -t build-decoder ./decoder
  mkdir -p "$DEFAULT_BUILD_OUT_DIR"
  docker run --rm \
    -v "$(pwd)/decoder":/decoder \
    -v "$(pwd)/$DEFAULT_GLOBAL_SECRETS":/global.secrets \
    -v "$(pwd)/$DEFAULT_BUILD_OUT_DIR":/out \
    -e DECODER_ID="$DEFAULT_DECODER_ID" \
    build-decoder
  ;;
flash)
  if [ $# -lt 1 ]; then
    echo "Usage: $0 flash <PORT>"
    exit 1
  fi
  PORT="$1"
  echo -e "\n\033[1mFlashing board on port ${PORT}...\033[0m\n"
  python -m ectf25.utils.flash "./$DEFAULT_BUILD_OUT_DIR/max78000.bin" "$PORT"
  ;;
subscribe)
  if [ $# -lt 2 ]; then
    echo "Usage: $0 subscribe <PORT> <CHANNEL1> [CHANNEL2 ...]"
    exit 1
  fi
  PORT="$1"
  shift
  mkdir -p subscriptions
  for CHANNEL in "$@"; do
    SUB_BIN="subscriptions/subscription_${CHANNEL}.bin"
    echo -e "\n\033[1mDeleting any existing subscription for channel ${CHANNEL}...\033[0m\n"
    rm -f "$SUB_BIN"
    echo -e "\n\033[1mGenerating subscription for channel ${CHANNEL}...\033[0m\n"
    python -m ectf25_design.gen_subscription "$DEFAULT_GLOBAL_SECRETS" "$SUB_BIN" "$DEFAULT_DECODER_ID" 1 18446744073709551615 "$CHANNEL"
    echo -e "\n\033[1mApplying subscription for channel ${CHANNEL} on port ${PORT}...\033[0m\n"
    python3 -m ectf25.tv.subscribe "$SUB_BIN" "$PORT"
  done
  ;;
test)
  if [ $# -lt 1 ]; then
    echo "Usage: $0 test {encode|decode|regular} [arguments...]"
    exit 1
  fi
  TEST_TYPE="$1"
  shift
  case "$TEST_TYPE" in
  encode)
    echo -e "\n\033[1mRunning encode stress test...\033[0m\n"
    python -m tools.ectf25.utils.stress_test encode "$DEFAULT_GLOBAL_SECRETS" --dump "$DEFAULT_STRESS_TEST_JSON"
    ;;
  decode)
    if [ $# -lt 2 ]; then
      echo "Usage: $0 test decode <PORT> <CHANNEL1> [CHANNEL2 ...]"
      exit 1
    fi
    PORT="$1"
    shift
    CHANNELS="$*"
    echo -e "\n\033[1mRunning decode stress test on port ${PORT} with channels: ${CHANNELS}\033[0m\n"
    python -m tools.ectf25.utils.stress_test --channels $CHANNELS decode "$PORT" "$DEFAULT_STRESS_TEST_JSON"
    ;;
  regular)
    if [ $# -lt 3 ]; then
      echo "Usage: $0 test regular <PORT> <FRAME_LENGTH> <CHANNEL1> [CHANNEL2 ...]"
      exit 1
    fi
    PORT="$1"
    FRAME_LENGTH="$2"
    shift 2
    CHANNELS="$*"
    echo -e "\n\033[1mRunning regular test on port ${PORT} with channels: ${CHANNELS} and frame length: ${FRAME_LENGTH}\033[0m\n"
    python -m ectf25.utils.tester --port "$PORT" -s "$DEFAULT_GLOBAL_SECRETS" rand -c $CHANNELS -f "$FRAME_LENGTH"
    ;;
  *)
    echo "Unknown test type: $TEST_TYPE"
    echo "Usage: $0 test {encode|decode|regular} [arguments...]"
    exit 1
    ;;
  esac
  ;;
*)
  echo "Unknown command: $CMD"
  echo "Usage: $0 {build|flash|subscribe|test} [arguments...]"
  exit 1
  ;;
esac
