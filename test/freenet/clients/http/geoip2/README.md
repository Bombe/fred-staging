# MaxMind GeoIP2 Database Interface

This package contains a thin layer over the MaxMind-DB reader package supplied
by MaxMind.

## Testing

For testing this code without requiring the user to download a full copy of the
Country database, a reduced database file containing only a couple of addresses
 is included. This file was created by the following perl script:
 
 ```perl
 use MaxMind::DB::Writer::Tree;
 
 my %types = (
     country => 'map',
     iso_code => 'utf8_string',
 );
 
 my $tree = MaxMind::DB::Writer::Tree->new(
     ip_version            => 6,
     record_size           => 24,
     database_type         => 'Freenet Test DB',
     languages             => ['en'],
     description           => { en => 'Freenet Test Database' },
     map_key_type_callback => sub { $types{ $_[0] } },
 );
 
 $tree->insert_network('1.2.3.4/32', { country => { iso_code => 'X0' }});
 $tree->insert_network('2.3.4.0/24', { country => { iso_code => 'X1' }});
 $tree->insert_network('1:2:3:4:5:6:7:8/64', { country => { iso_code => 'X2' }});
 $tree->insert_network('2:3:4:5:6:7:8:9/32', { country => { iso_code => 'X3' }});
 
 open my $fh, '>:raw', 'freenet-test-db.mmdb';
 $tree->write_tree($fh);
 ```
 
