PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
FORMAT=wav
TARGET_FORMAT=flac
FILEPATH='/media/Music/Girls Generation/Mr.Mr.'
FILE=$FILEPATH/*.$FORMAT
#[ -z $1 ] && echo "Argument to media path is needed" && exit 1

for file in $FILE
do
   /usr/lib/jellyfin-ffmpeg/ffmpeg -i $file -af aformat=s16:44100 ${file%.$FORMAT}.$TARGET_FORMAT
done

