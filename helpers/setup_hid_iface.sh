if [ -z "$1" ]
  then
    echo "param 1: Teensyduino location"
    exit 1
fi

file="$1/Contents/Java/hardware/teensy/avr/cores/teensy3/usb_desc.h"

cat $file

sed -i.bu 's/#define RAWHID_USAGE_PAGE /& 0xf1d0\n\/\/ #define RAWHID_USAGE_PAGE /g' $file
sed -i.bu 's/#define RAWHID_USAGE /& 0x01\n\/\/ #define RAWHID_USAGE_PAGE /g' $file
