from mininet.topo import Topo

class OneNodeTopo( Topo ):
    
    def __init__( self ):
        
        Topo.__init__( self )
        
        Server = self.addHost('server')
        Client = self.addHost('client')
        Switch1 = self.addSwitch('S1')
        
        self.addLink( Server, Switch1 )
        self.addLink( Switch1, Client )


topos = { '1-node-topo': (lambda: OneNodeTopo()) }