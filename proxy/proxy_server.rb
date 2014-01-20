class ProxyServer
  include Celluloid::IO

  def initialize
    @server = TCPServer.new(8080)
    async.run
  end

  def handle_connection(conn)
    puts "** Handling #{conn.inspect}"
    GoogleConnection.new(conn, "talk.google.com", "5223")

  rescue EOFError => e
    puts "EOF: #{e.message}"
  end

  def run
    while true do
      conn = @server.accept
      async.handle_connection(conn)
    end
  end
end