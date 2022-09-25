from mininet.topo import Topo

class ThreeNodeTopo( Topo ):
    
    def __init__( self ):
        
        Topo.__init__( self )
        
        Server = self.addHost('server')
        Client = self.addHost('client')
        Switch1 = self.addSwitch('S1')
        Switch2 = self.addSwitch('S2')
        Switch3 = self.addSwitch('S3')
        
        self.addLink( Server, Switch1 )
        self.addLink( Switch1, Switch2 )
        self.addLink( Switch2, Switch3 )
        self.addLink( Switch3, Client )
                
topos = { '3-node-topo': (lambda: ThreeNodeTopo()) }