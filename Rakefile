require 'rubygems'
require 'hoe'

Hoe.plugin :git
Hoe.plugin :minitest
Hoe.plugin :travis

Hoe.spec 'ruby-growl' do
  developer 'Eric Hodel', 'drbrain@segment7.net'

  spec_extras['required_ruby_version'] = '>= 1.9.2'

  rdoc_locations << 'docs.seattlerb.org:/data/www/docs.seattlerb.org/ruby-growl/'
  rdoc_locations << 'drbrain@rubyforge.org:/var/www/gforge-projects/ruby-growl/'

  license 'BSD 3-clause'

  extra_deps << ['uuid', '~> 2.3', '>= 2.3.5']
  dependency 'minitest', '~> 5.0', :developer
end

