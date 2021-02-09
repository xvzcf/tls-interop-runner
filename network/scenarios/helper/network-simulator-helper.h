/*
 * SPDX-FileCopyrightText: 2019 Jana Iyengar, Marten Seemann
 * SPDX-License-Identifier: Apache-2.0
 * This file is taken from https://github.com/marten-seemann/quic-network-simulator
 * and has been modified by the tls-interop-runner Authors.
 */

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
