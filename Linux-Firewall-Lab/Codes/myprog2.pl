#!/usr/bin/perl -w
use strict;
use warnings;
# Forces a flush after every write or print on the STDOUT
select STDOUT; $| = 1;
# Get the input line by line from the standard input.
# Each line contains an URL and some other information.
while (<>)
{
   my @parts = split;
   my $url = $parts[0];
   # If you copy and paste this code from this PDF file,
   # the ~(tilde) character may not be copied correctly.
   # Remove it, and then type the character manually.
   #if ($url =~ m#^http://foo\.example\.com(/.*)?#i) {
   #}
   if ($url =~ /\.(jpg|bmp|gif|jpeg)/) {
     # URL Rewriting
      print "http://www.cis.syr.edu/~wedu/seed/img/setup_img.png\n";
   }
   else {
     # No Rewriting.
     print "\n";
   }
}

