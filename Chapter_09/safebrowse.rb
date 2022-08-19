require 'msf/core'


class MetasploitModule < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        	=> 'Safe Browing API Check',
			'Version'     	=> '$Revision:$',
			'Description'	=> "Checks Google's safe browsing list",
			'Author'        => ['Daniel Graham'],
			'License'	=> MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'https://developers.google.com/safe-browsing/v4/lookup-api' ],
					[ 'URL', 'https://console.cloud.google.com'],
				]
		)
		register_options(
			[
				Opt::RHOST('safebrowsing.googleapis.com'),
				Opt::RPORT('443'),
				OptBool.new('SSL', [true, 'Use SSL', true]),				
				OptString.new('TARGET_URL', [ true, 'URL to Check', '']), 
				OptString.new('API_KEY', [ true, 'API Key', '']),
				OptString.new('PLATFORM', [ false, 'Threat Types', 'WINDOWS']),
			], self.class)
	
	end

	def run
	
		begin
			url = datastore['TARGET_URL']
			apiKey = datastore['API_KEY']
			platform = datastore['PLATFORM']
			postrequest =%{
			{
			    "client": {
			      "clientId":      "Metasploit Framework",
			      "clientVersion": "1.5.2"
			    },
			    "threatInfo": {
			      "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING"],
			      "platformTypes":    ["#{platform}"],
			      "threatEntryTypes": ["URL"],
			      "threatEntries": [
				{"url": "#{url}"},
			      ]
			    }
			  }
			}

			

			res = send_request_cgi({
				'uri'     => "/v4/threatMatches:find?key=#{apiKey}",
				'version' => "1.1",
				'method'  => 'POST',
				'data'    => postrequest,
				'headers' =>
					{
						'Content-Type' =>  'application/json',
					}
			}, 25)
			
			print("Result #{res}") #this outputs entire response, could probably do without this but its nice to see whats going on
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE =>e
			puts e.message
	end
end

