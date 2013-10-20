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

require 'facter'

# build a fact that lists all the valid macros available for use in rules files
macroprefix = 'macro.'
macrodir = '/usr/share/shorewall/'			# TODO: get from global
valid_macrodir = macrodir.gsub(/\/$/, '')+'/'		# ensure trailing slash

macros = []						# create list of values

if File.directory?(valid_macrodir)
	Dir.glob(valid_macrodir+macroprefix+'*').each do |f|
		b = File.basename(f)
		g = b.split('.')	# macro.$value
		if g.length == 2 and (g.shift()+'.') == macroprefix
			value = g[0]

			# skip over files with , (commas) in their names...
			if not(value.include? ',')
				macros.push(value)
			end
		end
	end
end

# now create the fact...
Facter.add('shorewall_macros') do
	#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
	setcode {
		macros.join(',')
	}
end

