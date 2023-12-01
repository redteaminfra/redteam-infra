#!/usr/bin/env bash

cd /opt/mythic

# Function to start Mythic
start_mythic() {
  echo "Starting Mythic..."
  ./mythic-cli start >/dev/null 2>&1
}

# Function to remove Mythic
remove_mythic() {
  echo "Mythic is not fully running. Attempting to reinstall..."
  ./mythic-cli stop
  ./mythic-cli uninstall
  docker rm $(docker ps -a -q --filter "name=mythic")
  sleep 10
}

# Function to check if Mythic is running
is_mythic_running() {
  local count=$(docker ps -a --filter "name=mythic" | grep -c "(healthy)")
  [ $count -eq 8 ]
}

# Function to wait for Mythic to start
wait_for_start() {
  for i in {1..10}; do
      if is_mythic_running; then
          echo "Mythic is fully running."
          return
      fi
      sleep 30
  done
  echo "Failed to start Mythic within the expected time."
}

# Main loop to ensure Mythic starts
for i in {1..3}; do
    start_mythic
    wait_for_start && exit 0
    remove_mythic
done

echo "Mythic failed to start after multiple attempts."
exit 1
