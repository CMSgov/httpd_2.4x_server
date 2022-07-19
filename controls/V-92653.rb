control 'V-92653' do
  title "The Apache web server must have resource mappings set to disable the
serving of certain file types."
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and cannot be served to a user, the web
server could deliver to a user web server configuration files, log files,
password files, etc.

    The web server must only allow hosted application file types to be served
to a user, and all other types must be disabled.


  "
  desc  'rationale', ''
  desc  'check', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Review any \"Action\" or \"AddHandler\" directives:

    # cat /<path_to_file>/httpd.conf | grep -i \"Action\"
    # cat /<path_to_file>/httpd.conf | grep -i \"AddHandler\"

    If \"Action\" or \"AddHandler\" exist and they configure .exe, .dll, .com,
.bat, or .csh, or any other shell as a viewer for documents, this is a finding.

    If this is not documented and approved by the Information System Security
Officer (ISSO), this is a finding.
  "
  desc 'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Disable MIME types for .exe, .dll, .com, .bat, and .csh programs.

    If \"Action\" or \"AddHandler\" exist within the \"httpd.conf\" file and
they configure .exe, .dll, .com, .bat, or .csh, remove those references.

    Restart Apache: apachectl restart

    Ensure this process is documented and approved by the ISSO.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag satisfies: %w(SRG-APP-000141-WSR-000081 SRG-APP-000141-WSR-000083)
  tag gid: 'V-92653'
  tag rid: 'SV-102741r1_rule'
  tag stig_id: 'AS24-U1-000300'
  tag fix_id: 'F-98895r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  config_path = input('config_path')

  describe apache_conf(config_path) do
    its('AddHandler.to_s') { should_not match '.exe' }
    its('AddHandler.to_s') { should_not match '.dll' }
    its('AddHandler.to_s') { should_not match '.com' }
    its('AddHandler.to_s') { should_not match '.bat' }
    its('AddHandler.to_s') { should_not match '.csh' }
  end

  describe apache_conf(config_path) do
    its('Action.to_s') { should_not match '.exe' }
    its('Action.to_s') { should_not match '.dll' }
    its('Action.to_s') { should_not match '.com' }
    its('Action.to_s') { should_not match '.bat' }
    its('Action.to_s') { should_not match '.csh' }
  end
end
