#ifndef NETWORK_SIMULATOR_HELPER_H
#define NETWORK_SIMULATOR_HELPER_H

#include "ns3/node.h"

using namespace ns3;

class NetworkSimulatorHelper {
public:
  NetworkSimulatorHelper();
  void Run(Time);
  Ptr<Node> GetServerNode() const;
  Ptr<Node> GetClientNode() const;

private:
  void RunSynchronizer() const;
  Ptr<Node> server_node_, client_node_;
};

#endif /* NETWORK_SIMULATOR_HELPER_H */
