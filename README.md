## pflightbar
A little utility for OpenBSD on the Chromebook Pixel to flash the lightbar red when
pf blocks a packet.
([Demo](https://twitter.com/jcs/status/784821967258017794))

### Usage
Make sure the `pflog0` device exists (usually created by `/etc/rc.d/pflogd`) and that blocked
traffic is sent to it via a `pf` rule:

    block return log

Then just run `pflightbar &` as root.
It will initialize the `pcap` device, open `/dev/chromeec`, `chroot` to `/var/empty`
and then drop privileges to `nobody`.

`pflightbar` will load some "lightbyte" byte code into the lightbar's `program` sequence
to flash red through a full ramp up and back down.
This is used to minimize communication with the EC when flashing, rather than having to
send the full RGB and dim sequences every time.

When a blocked packet is sent to `pflog0`, `pflightbar` will see it and tell the lightbar
to run the `program` sequence to flash red, and then return to its normal (`S0`) sequence.
