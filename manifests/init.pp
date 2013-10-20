# Shorewall templating module by James
# Copyright (C) 2012-2013+ James Shubin
# Written by James Shubin <james@shubin.ca>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# README: This puppet module should be used by specifying a main entry point
# with one of ::configuration, ::directory, or ::standalone. After that, you
# add on any missing configs by using defines such as ::rule and ::nat or by
# creating additional files in your ::directory folder. Advanced users might
# also want to manually include the main shorewall class should they want to
# modify some of the sane default settings. Example: the firewall zone name.

# NOTE: it is recommended that you do this in the scope you're using shorewall
$FW = '$FW'				# make using $FW in shorewall easier

class shorewall(
	$fw = 'fw'	# change to rename the fw zone
) {
	# iptables service that comes with rhel/centos
	service { 'iptables':		# don't let this interfere
		enable => false,	# don't start on boot
		#ensure => stopped,	# this won't do anything useful here
	}

	package { 'shorewall':
		ensure => present,
	}

	# add a rule macro for puppet to shorewall
	file { '/usr/share/shorewall/macro.Puppet':
		owner => root,
		group => root,
		mode => 644,	# u=rw,go=r
		source => 'puppet:///modules/shorewall/macros/macro.Puppet',
		alias => 'macro-puppet',
		require => Package['shorewall'],
	}

	# add a rule macro for VRRP to shorewall
	file { '/usr/share/shorewall/macro.VRRP':
		owner => root,
		group => root,
		mode => 644,	# u=rw,go=r
		source => 'puppet:///modules/shorewall/macros/macro.VRRP',
		alias => 'macro-vrrp',
		require => Package['shorewall'],
	}

	# add a rule macro for Kerberos to shorewall
	file { '/usr/share/shorewall/macro.Kerberos':
		owner => root,
		group => root,
		mode => 644,	# u=rw,go=r
		source => 'puppet:///modules/shorewall/macros/macro.Kerberos',
		alias => 'macro-kerberos',
		require => Package['shorewall'],
	}

	service { 'shorewall':
		enable => true,			# start on boot
		ensure => running,		# ensure it stays running
		hasstatus => true,		# use status command to monitor
		hasrestart => true,		# use restart, not start; stop
		require => [
			Package['shorewall'],
			File['/etc/shorewall/shorewall.conf'],	# require this file from somewhere	# FIXME: will this work even if the file comes from ::standalone or ::directory ?
			Service['iptables'],	# ensure it gets stopped first
			File['macro-puppet'],
			File['macro-vrrp'],
			File['macro-kerberos'],
		],
	}

	shorewall::zone { "${fw}":	# add default fw zone
		type => 'firewall',
	}
}

class shorewall::configuration(
	# TODO: add options here
) {
	include shorewall

	file { '/etc/shorewall/':
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root,
		group => nobody,
		mode => 600,
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}

	file { '/etc/shorewall/shorewall.conf':
		content => template('shorewall/shorewall.conf.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}
}

# ::directory () can be combined with ::rules() and requires class:shorewall
class shorewall::directory(
	$source
) {
	include shorewall

	file { '/etc/shorewall/':
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root,
		group => nobody,
		mode => 600,
		source => $source,
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}
}

class shorewall::pattern(
	$pattern = ''
) {
	include shorewall

	$valid_pattern = $pattern ? {
		# TODO: add other patterns here
		default => 'standalone',
	}

	file { '/etc/shorewall/':
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root,
		group => nobody,
		mode => 600,
		source => "puppet:///modules/shorewall/${valid_pattern}/",
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}
}

class shorewall::zone::base {
	include shorewall
	file { '/etc/shorewall/zones':
		content => template('shorewall/base/zones.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}

	file { '/etc/shorewall/zones.d/':
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root,
		group => nobody,
		mode => 600,
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}
}

define shorewall::zone(
	$type = 'ipv4',
	$options = [],			# TODO: add option validation?
	# TODO: add support for in_options and out_options
	$comment = '',			# you're insane if you need to use this
	$ensure = present
) {
	include shorewall::zone::base

	$valid_type = $type ? {
		# NOTE: the firewall type is added automatically by this module
		'firewall' => 'firewall',
		'ipsec' => 'ipsec',
		'ipsec4' => 'ipsec4',
		'bport' => 'bport',
		'bport4' => 'bport4',
		'vserver' => 'vserver',
		#'ipv4' => 'ipv4',
		default => 'ipv4',
	}

	file { "/etc/shorewall/zones.d/${name}.zone":
		content => template('shorewall/zone.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
		ensure => $ensure,
	}
}

class shorewall::policy::base {
	include shorewall
	file { '/etc/shorewall/policy':
		content => template('shorewall/base/policy.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}

	file { '/etc/shorewall/policy.d/':
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root,
		group => nobody,
		mode => 600,
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}
}

# invocation examples for shorewall::policy
# $source and $dest can each be either strings or arrays, $name is just a name.
#	shorewall::policy { "$name":
#		source => $source,
#		dest => $dest,
#		policy => 'DROP',
#	}
#
# $source and $dest can each be either strings or arrays
#	shorewall::policy { $source:
#		dest => $dest,
#		policy => 'REJECT',
#		logging => 'info',
#	}
#
# $source and $dest must each be a string
#	shorewall::policy { "${source}-${dest}":
#		policy => 'ALLOW',
#	}

define shorewall::policy(
	$source = '',
	$dest = '',
	$policy = 'REJECT',	# default policy should be reject so we notice!
	$logging = '',		# logging off by default to avoid log insanity!	# TODO: the 'loglevel' variable is stolen internally by puppet, what should we call this?
	$comment = '',
	$swap = false,		# swap $source and $dest semantics (advanced!)
	$ensure = present
) {
	include shorewall::policy::base

	# TODO: check that $source and $dest are in zone list, '$FW' or 'all', NOTE: we can only test zone list when not using shorewall::directory or shorewall::standalone because if so we won't have the shorewall::zone objects to look for...

	$split = split($name, '-')	# do some $name parsing
	$a = $split[0]	# source
	$b = $split[1]	# dest

	if ( "${a}" == "${name}" ) {	# then there are no dashes present!
		# set the source...
		if ( $source == '' ) {	# $source is empty, $a is $source
			$source_array = ["${a}"]

		} else {	# $source is not empty, $name is just a $name
			# is $source an [] or a single zone ?
			if is_array($source) {
				$source_array = $source
			} else {
				$source_array = ["${source}"]
			}
		}

		# set the dest...
		if is_array($dest) {	# is $dest an [] or a single zone ?
			$dest_array = $dest
		} else {
			$dest_array = ["${dest}"]
		}

	} elsif ( "${a}-${b}" == "${name}" ) {
		# then we have the simple source-dest case
		if ( "${source}" != '' ) or ( "${dest}" != '' ) {
			fail('Both $source and $dest must be empty when using a patterned $source-$dest $name.')
		}
		# each array has only one element
		$source_array = ["${a}"]
		$dest_array = ["${b}"]
	} else {
		fail('Policy $name must be either a $source or $source-$dest pattern.')
	}

	# When using create_resources with a source zone (as a string) and a
	# hash of {dest1 => {...}, dest2 => {...}} it is very easy to simply
	# swap the $source and $dest semantics and avoid having to transform
	# the input hash. create_resources accepts a hash of default params,
	# which very elegantly lets us specify: 'swap' => true and 'source'.
	# Example:
	#	create_resources(
	#		'shorewall::policy',
	#		merge($policy1, $policy2, $policyN),
	#		{'dest' => "${zone}", 'swap' => true}
	#	)
	# The defaults key 'dest' actually refers to 'source' after swapping.
	# Note: this causes duplicate resource problems in the complex cases.
	if $swap {
		$fixed_source_array = $dest_array
		$fixed_dest_array = $source_array
	} else {
		$fixed_source_array = $source_array
		$fixed_dest_array = $dest_array
	}

	$valid_policy = inline_template('<%= policy.upcase %>') ? {
		'ACCEPT' => 'ACCEPT',
		'DROP' => 'DROP',
		'REJECT' => 'REJECT',
		'CONTINUE' => 'CONTINUE',
		'QUEUE' => 'QUEUE',
		'NFQUEUE' => 'NFQUEUE',
		'NONE' => 'NONE',
		# TODO: does this need to be changed to support 'queuenumber' ?
		# TODO: maybe warn if default was used in case of a user typo ?
		default => 'REJECT',
	}

	$valid_loglevel = inline_template('<%= logging.downcase %>') ? {
		# FIXME: add more log levels here
		'info' => 'info',
		default => $logging,	# TODO: do we allow custom logging ???
	}

	file { "/etc/shorewall/policy.d/${name}.policy":
		content => template('shorewall/policy.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
		ensure => $ensure,
	}
}

class shorewall::interface::base {
	include shorewall
	file { '/etc/shorewall/interfaces':
		content => template('shorewall/base/interfaces.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}

	file { '/etc/shorewall/interfaces.d/':
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root,
		group => nobody,
		mode => 600,
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}
}

define shorewall::interface(
	$interface,
	$broadcast = 'detect',
	$physical = 'eth0',
	$options = [],
	$comment = '',
	$ensure = present
) {
	include shorewall::interface::base
	# TODO: 'physical' should be required, and if interface is not given then it defaults to UPPERCASE($name)+ '_IF'
	# the idea is that the 'NET_IF' string used internally can/should be generated from interface name...

	file { "/etc/shorewall/interfaces.d/${name}.interface":
		content => template('shorewall/interface.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
		ensure => $ensure,
	}
}

class shorewall::rule::base {
	include shorewall
	file { '/etc/shorewall/rules':
		content => template('shorewall/base/rules.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}

	file { '/etc/shorewall/rules.d/':
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root,
		group => nobody,
		mode => 600,
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}
}

# TODO:	have /etc/shorewall/rules be generated, and if at least one
#	::rule() is used, then include the 'SHELL CAT' part in the file

####################################################################
#ACTION      SOURCE DEST                PROTO DEST  SOURCE  ORIGINAL
#                                             PORT  PORT(S) DEST
define shorewall::rule(
	# TODO: add a $section option...
	$rule = '',
	$strip = true,			# do we run the whitespace cleaner ?
	# most of the following parameters are for non-text mode
	$action = '',			# REJECT or DNS(ACCEPT) or Ping(DROP)
	$source = '',			# source zone
	$source_ips = [],		# requires $source specified to be used
	$dest = '',			# dest zone
	$dest_ips = [],			# requires $dest specified to be used
	$proto = '',
	$port = [],			# dest ports list, ranges in form i:j
	$sport = [],			# source ports list, ranges in form i:j
	$original = [],			# original dest, list or strings valid!
	# TODO: add more fields here for all the other rule parameters...
	$comment = '',			# can be used in either text mode...
	$ensure = present,
	$debug = false
) {
	include shorewall::rule::base

	if "${rule}" == '' and "${action}" == '' {
		fail('You must specify at least $rule or $action.')
	}

	if "${rule}" != '' and "${action}" != '' {
		fail('You must only specify either $rule or $action.')
	}

	# figure out if we're using text mode or not automatically...
	if "${rule}" != '' {
		$bool_text = true
	}

	if "${action}" != '' {
		$bool_text = false
	}

	if $bool_text {

		$valid_rule = $strip ? {
			# don't rm required newlines when using exact templates
			false => "${rule}",
			# remove white space at beginnings or ends of each line
			default => regsubst($rule, '(^\s+|\s+$)', '', 'G'),
		}

	} else {		# process multiple field, $text mode = false...
		# NOTE: there will be certain patterns that aren't supported...
		# this part doesn't catch everything, for stuff that doesn't
		# yet work, either use the text mode, or submit a bug/patch!

		# NOTE: the special regex chars that need to be escaped are:
		# . | ( ) [ ] { } + \ ^ $ * ?

		# NOTE: http://doc.infosnel.nl/ruby_regular_expressions.html

		$valid_macros = split($shorewall_macros, ',')	# from a fact !

		# parse the $action... the MACRO/TARGET format is deprecated...

		# match: TARGET such as: REJECT
		if $action =~ /^([A-Z]+[A-Z_]*)([\+\-!]?)$/ {
			if $debug {
				notify { "regex1-${name}":
					message => "match1: '${1}' & '{$2}'",
				}
			}

			$valid_macro = ''		# no macro is used
			$valid_target = "${1}"		# example is: DROP
			$valid_modifier = "${2}"	# $2 is the symbol

			$valid_action = "${valid_target}${valid_modifier}"

		# match: MACRO(TARGET) such as: SSH(ACCEPT)
		# TODO: inside (TARGET), a lot more complex stuff is allowed...
		# TODO: is a modifier allowed inside the ( & ) for the target ?
		} elsif $action =~ /^([A-Z]+[A-Za-z0-9]*)\(([A-Z]+[A-Z]*)([\+\-!]?)\)$/ {
			if $debug {
				notify { "regex2-${name}":
					message => "match2: '${1}' & '${2}' & '${3}'",
				}
			}

			$valid_macro = "${1}"
			$valid_target = "${2}"
			$valid_modifier = "${3}"
			if ! member($valid_macros, $valid_macro) {
				# don't fail because the $valid_macros fact is
				# only created after puppet has been run once!
				warning("Invalid macro: '${valid_macro}' ?")
			}

			$valid_action = "${valid_macro}(${valid_target}${valid_modifier})"

		# NOTE: this section matches the deprecated MACRO/TARGET syntax
		# NOTE: it is almost identical to the above regex and code body
		} elsif $action =~ /^([A-Z]+[A-Za-z0-9]*)\/([A-Z]+[A-Z]*)([\+\-!]?)$/ {
			if $debug {
				notify { "regex3-${name}":
					message => "match2: '${1}' & '${2}' & '${3}'",
				}
			}

			$valid_macro = "${1}"
			$valid_target = "${2}"
			$valid_modifier = "${3}"
			if ! member($valid_macros, $valid_macro) {
				# don't fail because the $valid_macros fact is
				# only created after puppet has been run once!
				warning("Invalid macro: '${valid_macro}' ?")
			}

			$valid_action = "${valid_macro}(${valid_target}${valid_modifier})"

		# unmatched !
		} else {
			# NOTE: certain valid patterns will fail because this
			# regex and puppet module are not yet advanced enough
			# please report valid actions that are commonly used!
			fail("Invalid action: '${action}' ?")
		}

		# TODO: require => Shorewall::Zone[$source/$dest?] if all zones were created by zone objects...
		$valid_source = $source ? {
			'' => '-',					# skip!
			default => "${source}",
		}

		$valid_dest = $dest ? {
			'' => '-',					# skip!
			default => "${dest}",
		}

		# BUG: lol: https://projects.puppetlabs.com/issues/15813
		$source_ips_array = type($source_ips) ? {
			'array' => $source_ips,
			default => [$source_ips],
		}

		$dest_ips_array = type($dest_ips) ? {
			'array' => $dest_ips,
			default => [$dest_ips],
		}

		$full_source = "${valid_source}" ? {
			'-' => '-',	# can't specify :source_ips if skipping
			default => "${source_ips_array}" ? {	# full source column
				'' => "${valid_source}",
				default => sprintf("${valid_source}:%s", join($source_ips_array, ',')),
			}
		}

		$full_dest = "${valid_dest}" ? {
			'-' => '-',	# can't specify :dest_ips if skipping
			default => "${dest_ips_array}" ? {	# full dest column
				'' => "${valid_dest}",
				default => sprintf("${valid_dest}:%s", join($dest_ips_array, ',')),
			}
		}

		$valid_proto = $proto ? {
			'' => $valid_macro ? {	# select protocol automatically
				'' => '-',	# this is an empty protocol...?	# XXX: what should we do here ?
					# hope any valid macro sets a protocol!
				default => '-'	# skip over picking a protocol!
			},
			default => "${proto}",	# a manually specified protocol
		}

		$valid_port = "${port}" ? {
			'' => '-',	# match empty arrays or an empty string
			# first create a one element array from the input, then
			# flatten and join; string or list inputs now both work
			default => sprintf("%s", join(flatten([$port]), ',')),
		}

		$valid_sport = "${sport}" ? {
			'' => '-',	# match empty arrays or an empty string
			# first create a one element array from the input, then
			# flatten and join; string or list inputs now both work
			default => sprintf("%s", join(flatten([$sport]), ',')),
		}

		$valid_original = "${original}" ? {
			'' => '-',	# match empty arrays or an empty string
			# first create a one element array from the input, then
			# flatten and join; string or list inputs now both work
			default => sprintf("%s", join(flatten([$original]), ',')),
		}

		$list = ["${valid_action}", "${full_source}", "${full_dest}", "${valid_proto}", "${valid_port}", "${valid_sport}", "${valid_original}"]
		$full = delete($list, '')	# remove empty entries!
		# now pop continuously from the right all sequential - (dash) elements!
		$done = split(inline_template("<%= while full[-1] == '-'; full.pop(); end; full.join('#') %>"), '#')
		$valid_rule = join($done, "\t")
	}

	file { "/etc/shorewall/rules.d/${name}.rule":
		content => template('shorewall/rule.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
		ensure => $ensure,
	}
}

class shorewall::masq::base {
	include shorewall
	file { '/etc/shorewall/masq':
		content => template('shorewall/base/masq.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}

	file { '/etc/shorewall/masq.d/':
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root,
		group => nobody,
		mode => 600,
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}
}

define shorewall::masq(
	$interface,			# eg: NET_IF
	$digit = '',			# eg: 1, to be used for NET_IF:1
	$source = [],			# eg: [192.168.123.0/24, etc...]
	$address = '',			# optional ipaddress for snat
	$comment = '',
	$ensure = present
) {
	include shorewall::masq::base

	# NOTE: $name is not being used as a configuration value here since it
	# is unclear what the correct (unique) primary key for this should be.

	file { "/etc/shorewall/masq.d/${name}.masq":
		content => template('shorewall/masq.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
		ensure => $ensure,
	}
}

class shorewall::nat::base {
	include shorewall
	file { '/etc/shorewall/nat':
		content => template('shorewall/base/nat.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}

	file { '/etc/shorewall/nat.d/':
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root,
		group => nobody,
		mode => 600,
		notify => Service['shorewall'],
		require => Package['shorewall'],
	}
}

define shorewall::nat(
	$external,			# eg: $net_vip_1
	$interface,			# eg: NET_IF
	$internal,			# eg: 192.168.123.x
	$allif = false,			# all interfaces option
	$local = false,			# local option
	$comment = '',
	$ensure = present
) {
	include shorewall::nat::base

	$print_allif = $allif ? {
		true => 'yes',
		default => 'no',
	}

	$print_local = $local ? {
		true => 'yes',
		default => 'no',
	}

	file { "/etc/shorewall/nat.d/${name}.nat":
		content => template('shorewall/nat.erb'),
		owner => root,
		group => root,
		mode => 600,	# u=rw
		notify => Service['shorewall'],
		require => Package['shorewall'],
		ensure => $ensure,
	}
}

