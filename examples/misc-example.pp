# here is some example usage for some of the shorewall classes and types
# there are not many examples, because most users are interested in this
# because they are using this module as a dependency for another module.
# however, i do think this is a great module! please check out the code,
# and if you need more documentation and/or examples, please contact me!

# most users will find this idiom very helpful so that puppet leaves $FW as $FW
$FW = '$FW'				# make using $FW in shorewall easier...

class { '::shorewall::configuration':
	# NOTE: no configuration specifics are needed at the moment
}

# define a zone
$zone = 'net'	# use a variable
shorewall::zone { "${zone}":
	type => 'ipv4',
	options => [],
}

shorewall::interface { "${zone}":
	interface => inline_template('<%= zone.upcase+"_IF" %>'),	# eg: NET_IF
	physical => 'eth1',
	options => ['tcpflags', 'routefilter', 'nosmurfs', 'logmartians'],
}

shorewall::policy { "$FW-${zone}":	# from the fw to the zone
	policy => 'ACCEPT',
}

shorewall::policy { "${zone}-all":
	policy => 'REJECT',
	logging => 'info',
}

# define a rule in the traditional shorewall way:
$net = $zone	# you may use your own variables!
shorewall::rule { 'kerberos': rule => "
Kerberos/ACCEPT  ${net}    $FW
", comment => 'Allow Kerberos for krb5 server on tcp/udp port 88.'}

# define a rule using the "library" friendly way.
# NOTE: other parameters are also supported here.
shorewall::rule { "icmp-${zone}":
	action => 'ACCEPT',
	source => '$FW',
	dest => "${zone}",
	comment => 'Allow icmp from the firewall zone.',
	ensure => present,
}

