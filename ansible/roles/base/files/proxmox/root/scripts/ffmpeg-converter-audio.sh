PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
FORMAT=wav
TARGET_FORMAT=flac
FILEPATH=${:-$1|"."}
FILE=$FILEPATH/*.$FORMAT

echo "$FORMAT this is your original codec"
echo "$TARGET_FORMAT this is target codec"
echo "$FILEPATH this is filepath to your media"
echo ".... PLEASE MAKE SURE ABOVE IS CORRECT ....."

sleep 5

for file in $FILE
do
   /usr/lib/jellyfin-ffmpeg/ffmpeg -i "'$file'" -af aformat=s16:44100 ${file%.$FORMAT}.$TARGET_FORMAT
done
