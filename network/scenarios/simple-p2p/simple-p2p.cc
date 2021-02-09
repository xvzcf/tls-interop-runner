/*
 * SPDX-FileCopyrightText: 2019 Jana Iyengar, Marten Seemann
 * SPDX-License-Identifier: Apache-2.0
 * This file is taken from https://github.com/marten-seemann/quic-network-simulator
 * and has been modified by the tls-interop-runner Authors.
 */

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "../helper/network-simulator-helper.h"
#include "../helper/point-to-point-helper.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ns3 simulator");

int main(int argc, char *argv[]) {
  std::string delay, bandwidth, queue;
  CommandLine cmd;
  cmd.AddValue("delay", "delay of the p2p link", delay);
  cmd.AddValue("bandwidth", "bandwidth of the p2p link", bandwidth);
  cmd.AddValue("queue", "queue size of the p2p link (in packets)", queue);
  cmd.Parse (argc, argv);

  NS_ABORT_MSG_IF(delay.length() == 0, "Missing parameter: delay");
  NS_ABORT_MSG_IF(bandwidth.length() == 0, "Missing parameter: bandwidth");
  NS_ABORT_MSG_IF(queue.length() == 0, "Missing parameter: queue");

  NetworkSimulatorHelper sim;

  // Stick in the point-to-point line between the sides.
  RunnerPointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue(bandwidth));
  p2p.SetChannelAttribute("Delay", StringValue(delay));
  p2p.SetQueueSize(StringValue(queue + "p"));

  NetDeviceContainer devices = p2p.Install(sim.GetClientNode(), sim.GetServerNode());

  sim.Run(Seconds(36000));
}
