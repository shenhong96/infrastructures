# 1. Encode category name
curl http://localhost:8080/api/v2/torrents/categories | jq '.'
CATEGORY="海棠曲艺 htpt"
ENCODED_CATEGORY=$(printf '%s' "$CATEGORY" | jq -sRr @uri)

# 2. Get torrent hashes
HASHES=$(curl -s "http://localhost:8080/api/v2/torrents/info?category=$ENCODED_CATEGORY" | jq -r '.[].hash')

# 3. Add tracker to each torrent
NEW_TRACKER="https://tracker.example.com/announce"
for hash in $HASHES; do
  curl -d "hash=$hash&urls=$NEW_TRACKER" \
    http://localhost:8080/api/v2/torrents/addTrackers
done
