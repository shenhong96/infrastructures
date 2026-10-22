#!/bin/bash
# Rename this path to and do not end with a "/", to the
# folder that contains the movie and subtitles
#
subtitle_folder=/mnt/storage/media

for i in $(ls $subtitle_folder/*.srt)
do
#	echo $i
	mv $i ${i%.srt}.chs.srt
done


