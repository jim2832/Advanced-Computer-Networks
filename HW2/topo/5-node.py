from mininet.topo import Topo

class FiveNodeTopo( Topo ):
    
    def __init__( self ):
        
        Topo.__init__( self )
        
        Server = self.addHost('server')
        Client = self.addHost('client')
        Switch1 = self.addSwitch('S1')
        Switch2 = self.addSwitch('S2')
        Switch3 = self.addSwitch('S3')
        Switch4 = self.addSwitch('S4')
        Switch5 = self.addSwitch('S5')
        
        self.addLink( Server, Switch1 )
        self.addLink( Switch1, Switch2 )
        self.addLink( Switch2, Switch3 )
        self.addLink( Switch3, Switch4 )
        self.addLink( Switch4, Switch5 )
        self.addLink( Switch5, Client )
                
topos = { '5-node-topo': (lambda: FiveNodeTopo()) }