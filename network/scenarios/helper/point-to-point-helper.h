/*
 * SPDX-FileCopyrightText: 2019 Jana Iyengar, Marten Seemann
 * SPDX-License-Identifier: Apache-2.0
 * This file is taken from https://github.com/marten-seemann/quic-network-simulator
 * and has been modified by the tls-interop-runner Authors.
 */

#ifndef POINT_TO_POINT_HELPER_HH
#define POINT_TO_POINT_HELPER_HH

#include "ns3/point-to-point-module.h"

using namespace ns3;

// The QuicPointToPointHelper acts like the ns3::PointToPointHelper,
// but sets a ns3::DropTailQueue to one packet in order to minimize queueing latency.
// Queues are simulated using a PfifoFastQueueDisc, with a default size of 100 packets.
// The queue size can be set to a custom value using SetQueueSize().
class RunnerPointToPointHelper : public PointToPointHelper {
public:
  RunnerPointToPointHelper();

  // SetQueueSize sets the queue size for the PfifoFastQueueDisc
  void SetQueueSize(StringValue);
  NetDeviceContainer Install(Ptr<Node> a, Ptr<Node> b);
private:
  StringValue queue_size_; // for the PfifoFastQueueDisc
};

#endif /* POINT_TO_POINT_HELPER_HH */
