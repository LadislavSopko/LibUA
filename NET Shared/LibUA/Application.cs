using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LibUA.Core;
using Microsoft.Extensions.Logging;

namespace LibUA
{
    namespace Server
    {
        public abstract class Application
        {
            protected struct ServerMonitorKey : IEquatable<ServerMonitorKey>
            {
                public ServerMonitorKey(NodeId nodeId, NodeAttribute attribute)
                {
                    this.NodeId = nodeId;
                    this.Attribute = attribute;
                }

                public ServerMonitorKey(ReadValueId itemToMonitor)
                    : this(itemToMonitor.NodeId, itemToMonitor.AttributeId)
                {
                }

                public NodeId NodeId;

                public NodeAttribute Attribute;

                public override int GetHashCode()
                {
                    return (int)(NodeId.GetHashCode() ^ (int)Attribute);
                }

                public override bool Equals(object obj)
                {
                    if (obj is ServerMonitorKey)
                    {
                        return NodeId == ((ServerMonitorKey)obj).NodeId &&
                            Attribute == ((ServerMonitorKey)obj).Attribute;
                    }

                    return false;
                }

                public bool Equals(ServerMonitorKey other)
                {
                    return NodeId.Equals(other.NodeId) && Attribute == other.Attribute;
                }
            }

            public struct SessionCreationInfo
            {
                public EndPoint Endpoint;
            }

            protected ILogger _logger; // this will come form outside

            internal ConcurrentDictionary<NodeId, Node> _AddressSpaceTable;

            protected ConcurrentDictionary<NodeId, Node> AddressSpaceTable { get => _AddressSpaceTable; }

            HashSet<NodeId> internalAddressSpaceNodes;
            Dictionary<NodeId, object> internalAddressSpaceValues;

            ReaderWriterLockSlim monitorMapRW;
            Dictionary<ServerMonitorKey, List<MonitoredItem>> monitorMap;

            public delegate bool MethodCallHandler(object session, CallMethodRequest req);
            public Dictionary<NodeId, MethodCallHandler> MethodMap;

            public virtual X509Certificate2 ApplicationCertificate
            {
                get { return null; }
            }

            public virtual RSACryptoServiceProvider ApplicationPrivateKey
            {
                get { return null; }
            }

            protected Application(ILogger l = null)
            {
                _logger = l;

                MethodMap = new Dictionary<NodeId, MethodCallHandler>();

                _AddressSpaceTable = new ConcurrentDictionary<NodeId, Node>();

                this.MakeDefaultNodes();

                // Missing in the auto-generated UA specification
                // BaseDataType organizes DataTypesFolder
                _AddressSpaceTable[new NodeId(UAConst.BaseDataType)].References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), new NodeId(UAConst.DataTypesFolder), false));

                SetupInternalAddressSpace();

                monitorMapRW = new ReaderWriterLockSlim();
                monitorMap = new Dictionary<ServerMonitorKey, List<MonitoredItem>>();
            }

            public virtual bool MonitorAdd(object session, MonitoredItem mi)
            {
                Node node;
                if (!_AddressSpaceTable.TryGetValue(mi.ItemToMonitor.NodeId, out node) ||
                    !SessionHasPermissionToRead(session, mi.ItemToMonitor.NodeId))
                {
                    return false;
                }

                var key = new ServerMonitorKey(mi.ItemToMonitor);

                try
                {
                    monitorMapRW.EnterWriteLock();

                    List<MonitoredItem> mis = null;
                    if (monitorMap.TryGetValue(key, out mis))
                    {
                        mis.Add(mi);
                    }
                    else
                    {
                        mis = new List<MonitoredItem>();
                        mis.Add(mi);
                        monitorMap.Add(key, mis);
                    }
                }
                finally
                {
                    monitorMapRW.ExitWriteLock();
                }

                return true;
            }

            public virtual void MonitorRemove(object session, MonitoredItem mi)
            {
                var key = new ServerMonitorKey(mi.ItemToMonitor);
                try
                {
                    monitorMapRW.EnterWriteLock();
                    List<MonitoredItem> mis = null;
                    if (monitorMap.TryGetValue(key, out mis))
                    {
                        mis.Remove(mi);
                    }
                }
                finally
                {
                    monitorMapRW.ExitWriteLock();
                }
            }

            public virtual void MonitorNotifyDataChange(NodeId id, DataValue dv)
            {
                var key = new ServerMonitorKey(id, NodeAttribute.Value);
                //Console.WriteLine("{0} {1}", id.ToString(), dv.Value.ToString());

                try
                {
                    monitorMapRW.EnterReadLock();
                    List<MonitoredItem> mis = null;
                    if (monitorMap.TryGetValue(key, out mis))
                    {
                        for (int i = 0; i < mis.Count; i++)
                        {
                            if (mis[i].QueueData.Count >= mis[i].QueueSize)
                            {
                                mis[i].QueueOverflowed = true;
                            }
                            else
                            {
                                mis[i].QueueData.Enqueue(dv);
                            }

                            if (mis[i].ParentSubscription.ChangeNotification == Subscription.ChangeNotificationType.None)
                            {
                                mis[i].ParentSubscription.ChangeNotification = Subscription.ChangeNotificationType.AtPublish;
                            }
                        }
                    }
                }
                finally
                {
                    monitorMapRW.ExitReadLock();
                }
            }

            public virtual void MonitorNotifyEvent(NodeId id, EventNotification ev)
            {
                var key = new ServerMonitorKey(id, NodeAttribute.EventNotifier);
                //Console.WriteLine("{0} {1}", id.ToString(), dv.Value.ToString());

                try
                {
                    monitorMapRW.EnterReadLock();
                    List<MonitoredItem> mis = null;
                    if (monitorMap.TryGetValue(key, out mis))
                    {
                        for (int i = 0; i < mis.Count; i++)
                        {
                            if (mis[i].QueueEvent.Count >= mis[i].QueueSize)
                            {
                                mis[i].QueueOverflowed = true;
                            }
                            else
                            {
                                mis[i].QueueEvent.Enqueue(ev);
                            }

                            if (mis[i].ParentSubscription.ChangeNotification == Subscription.ChangeNotificationType.None)
                            {
                                mis[i].ParentSubscription.ChangeNotification = Subscription.ChangeNotificationType.AtPublish;
                            }
                        }
                    }
                }
                finally
                {
                    monitorMapRW.ExitReadLock();
                }
            }

            public virtual object SessionCreate(SessionCreationInfo sessionInfo)
            {
                return null;
            }

            public virtual bool SessionValidateClientApplication(object session, ApplicationDescription clientApplicationDescription, byte[] clientCertificate, string sessionName)
            {
                return true;
            }

            public virtual bool SessionValidateClientUser(object session, object userIdentityToken)
            {
                return true;
            }

            public virtual bool SessionActivateClient(object session, SecurityPolicy securityPolicy, MessageSecurityMode messageSecurityMode, X509Certificate2 remoteCertificate)
            {
                return true;
            }

            public virtual void SessionRelease(object session)
            {
            }

            public virtual Core.ApplicationDescription GetApplicationDescription(string endpointUrlHint)
            {
                return null;
            }

            public virtual IList<Core.EndpointDescription> GetEndpointDescriptions(string endpointUrlHint)
            {
                return new List<Core.EndpointDescription>();
            }

            protected virtual DataValue HandleReadRequestInternal(NodeId id)
            {
                object value;
                if (internalAddressSpaceValues.TryGetValue(id, out value))
                {
                    return new DataValue(value, StatusCode.Good);
                }
                
                else if (_AddressSpaceTable.TryGetValue(id, out Node node) && node is NodeVariable nv)
                {
                    DataValue temp = (DataValue)nv.Value;

                    if (_logger != null && _logger.IsEnabled(LogLevel.Trace))
                    {
                        _logger.LogTrace($"Value of node: {id} is {temp?.Value}");
                    }

                    return new DataValue(temp?.Value, StatusCode.Good, DateTime.Now);
                }

                return new DataValue(8788, StatusCode.Good);
            }

            void SetupInternalAddressSpace()
            {
                internalAddressSpaceNodes = new HashSet<NodeId>();
                foreach (var key in _AddressSpaceTable.Keys) { internalAddressSpaceNodes.Add(key); }

                internalAddressSpaceValues = new Dictionary<NodeId, object>()
                {
                    { new NodeId(UAConst.Server_ServerArray), new string[0] },
                    { new NodeId(UAConst.Server_NamespaceArray),new string[]
                        {
                            "http://opcfoundation.org/UA/",
                            "http://quantensystems.com/uaSDK2",
                            "http://quantensystems.com/NotUsed",
                            "http://3uvision.com/fenix"
                        }
                    },
                    { new NodeId(UAConst.Server_ServerStatus_State), (Int32)ServerState.Running }
                };
            }

            public bool IsSubtypeOrEqual(NodeId target, NodeId parent)
            {
                if (target.Equals(parent)) { return true; }
                if (parent.EqualsNumeric(0, 0)) { return true; }

                Node node;
                if (!_AddressSpaceTable.TryGetValue(parent, out node))
                {
                    return false;
                }

                for (int i = 0; i < node.References.Count; i++)
                {
                    var r = node.References[i];
                    if (r.IsInverse) { continue; }

                    if (!r.ReferenceType.EqualsNumeric(0, (uint)UAConst.HasSubtype))
                    {
                        continue;
                    }

                    if (IsSubtypeOrEqual(target, r.Target))
                    {
                        return true;
                    }
                }

                return false;
            }

            public virtual StatusCode HandleTranslateBrowsePathRequest(object session, BrowsePath path, List<BrowsePathTarget> res)
            {
                Node node;
                if (!_AddressSpaceTable.TryGetValue(path.StartingNode, out node) ||
                    !SessionHasPermissionToRead(session, path.StartingNode))
                {
                    return StatusCode.BadNodeIdUnknown;
                }

                for (int i = 0; i < path.RelativePath.Length; i++)
                {
                    var rp = path.RelativePath[i];
                    ReferenceNode nref = null;
                    for (int j = 0; j < node.References.Count; j++)
                    {
                        var tref = node.References[j];
                        if (rp.IsInverse != tref.IsInverse)
                        {
                            continue;
                        }

                        if (!rp.IncludeSubtypes && !tref.ReferenceType.Equals(rp.ReferenceTypeId))
                        {
                            continue;
                        }

                        if (rp.IncludeSubtypes && !IsSubtypeOrEqual(tref.ReferenceType, rp.ReferenceTypeId))
                        {
                            continue;
                        }

                        Node target;
                        if (!_AddressSpaceTable.TryGetValue(tref.Target, out target) ||
                            !SessionHasPermissionToRead(session, tref.Target))
                        {
                            continue;
                        }

                        if (target.BrowseName.Equals(rp.TargetName))
                        {
                            nref = node.References[j];
                            node = target;
                            break;
                        }
                    }

                    if (nref == null || node == null)
                    {
                        res.Add(new BrowsePathTarget() { Target = node.Id, RemainingPathIndex = (uint)i });
                        return StatusCode.BadNoMatch;
                    }
                }

                res.Add(new BrowsePathTarget() { Target = node.Id, RemainingPathIndex = (uint)path.RelativePath.Length });
                return StatusCode.Good;
            }

            public virtual StatusCode HandleBrowseRequest(object session, BrowseDescription browseDesc, List<ReferenceDescription> results, int maxResults, ContinuationPointBrowse cont)
            {
                Node node;
                if (!_AddressSpaceTable.TryGetValue(browseDesc.Id, out node) ||
                    !SessionHasPermissionToRead(session, browseDesc.Id))
                {
                    return StatusCode.BadNodeIdUnknown;
                }

                results.Clear();
                for (int i = cont.IsValid ? cont.Offset : 0; i < node.References.Count; i++)
                {
                    var r = node.References[i];

                    if (browseDesc.Direction == BrowseDirection.Forward && r.IsInverse ||
                        browseDesc.Direction == BrowseDirection.Inverse && !r.IsInverse)
                    {
                        continue;
                    }

                    if (!browseDesc.IncludeSubtypes && !r.ReferenceType.Equals(browseDesc.ReferenceType))
                    {
                        continue;
                    }

                    if (browseDesc.IncludeSubtypes && !IsSubtypeOrEqual(r.ReferenceType, browseDesc.ReferenceType))
                    {
                        continue;
                    }

                    if (results.Count == maxResults)
                    {
                        cont.Offset = i;
                        cont.IsValid = true;

                        // TODO: Set continuation point
                        return StatusCode.GoodMoreData;
                    }

                    NodeId typeDef = NodeId.Zero;
                    Node targetNode = null;
                    if (!_AddressSpaceTable.TryGetValue(r.Target, out targetNode) ||
                        !SessionHasPermissionToRead(session, r.Target))
                    {
                        results.Add(new ReferenceDescription(r.ReferenceType, !r.IsInverse, r.Target,
                            new QualifiedName(), new LocalizedText(string.Empty), NodeClass.Unspecified, typeDef));
                    }
                    else
                    {
                        if (targetNode.References != null && (targetNode is NodeObject || targetNode is NodeVariable))
                        {
                            for (int j = 0; j < targetNode.References.Count; j++)
                            {
                                if (targetNode.References[j].ReferenceType.EqualsNumeric(0, (uint)UAConst.HasTypeDefinition))
                                {
                                    typeDef = targetNode.References[j].Target;
                                }
                            }
                        }
                    }

                    results.Add(new ReferenceDescription(r.ReferenceType, !r.IsInverse, r.Target, targetNode.BrowseName, targetNode.DisplayName, targetNode.GetNodeClass(), typeDef));
                }

                //Console.WriteLine("Browse {0} {1} -> {2}",
                //	browseDesc.Id.ToString(), node.DisplayName.ToString(),
                //	results.Count == 0 ? "(no results)" :
                //	string.Join(", ", results.Select(r => r.DisplayName.ToString())));

                cont.IsValid = false;
                return StatusCode.Good;
            }

            public virtual UInt32[] HandleWriteRequest(object session, WriteValue[] writeValues)
            {
                var respStatus = new UInt32[writeValues.Length];
                for (int i = 0; i < writeValues.Length; i++)
                {
                    WriteValue temp_value = writeValues[i];
                    if (!_AddressSpaceTable.TryGetValue(temp_value.NodeId, out Node node))
                    {
                        respStatus[i] = (UInt32)StatusCode.BadNodeIdUnknown;
                    }
                    else if (node is NodeVariable nv)
                    {
                        nv.Value = temp_value.Value;
                        respStatus[i] = (UInt32)StatusCode.Good;
                    }
                    else
                    {
                        respStatus[i] = (UInt32)StatusCode.BadNotWritable;
                    }
                }

                return respStatus;
            }

            public virtual UInt32 HandleHistoryReadRequest(object session, object readDetails, HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<DataValue> results, ref int? offsetContinueFit)
            {
                return (UInt32)StatusCode.BadNotImplemented;
            }

            public virtual UInt32[] HandleHistoryUpdateRequest(object session, HistoryUpdateData[] updates)
            {
                UInt32[] resps = new UInt32[updates.Length];
                for (int i = 0; i < updates.Length; i++)
                {
                    resps[i] = (UInt32)StatusCode.BadNotImplemented;
                }

                return resps;
            }

            public virtual UInt32 HandleHistoryEventReadRequest(object session, object readDetails, HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<object[]> results)
            {
                return (UInt32)StatusCode.BadNotImplemented;
            }

            public virtual DataValue[] HandleReadRequest(object session, ReadValueId[] readValueIds)
            {
                var res = new DataValue[readValueIds.Length];

                for (int i = 0; i < readValueIds.Length; i++)
                {
                    Node node = null;
                    if (!_AddressSpaceTable.TryGetValue(readValueIds[i].NodeId, out node) ||
                        !SessionHasPermissionToRead(session, readValueIds[i].NodeId))
                    {
                        res[i] = new DataValue(null, StatusCode.BadNodeIdUnknown);
                        continue;
                    }

                    if (readValueIds[i].AttributeId == NodeAttribute.Value)
                    {

                        if (_logger != null && _logger.IsEnabled(LogLevel.Trace))
                        {
                            _logger.LogTrace($"Get value req for node: {readValueIds[i].NodeId}");
                        }

                        res[i] = HandleReadRequestInternal(readValueIds[i].NodeId);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.NodeId)
                    {
                        res[i] = new DataValue(node.Id, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.NodeClass)
                    {
                        NodeClass nodeClass = node.GetNodeClass();
                        res[i] = new DataValue((Int32)nodeClass, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.BrowseName)
                    {
                        res[i] = new DataValue(node.BrowseName, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.DisplayName)
                    {
                        res[i] = new DataValue(node.DisplayName, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.Description)
                    {
                        res[i] = new DataValue(node.Description, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.WriteMask)
                    {
                        res[i] = new DataValue(node.WriteMask, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.UserWriteMask)
                    {
                        res[i] = new DataValue(node.UserWriteMask, StatusCode.Good);
                    }
					else if (readValueIds[i].AttributeId == NodeAttribute.AccessRestrictions)
					{
                        /*
                         * This is a subtype of the UInt16 DataType with the OptionSetValues Property defined. It is used to define the access restrictions of a Node. 
                         * 
                         *  SigningRequired	    0	The Client can only access the Node when using a SecureChannel which digitally signs all messages.
                            EncryptionRequired	1	The Client can only access the Node when using a SecureChannel which encrypts all messages.
                            SessionRequired	    2	The Client cannot access the Node when using SessionlessInvoke Service invocation.
                         */

                        res[i] = new DataValue((UInt16)0, StatusCode.Good);
					}
                    else if (readValueIds[i].AttributeId == NodeAttribute.IsAbstract && node is NodeReferenceType)
                    {
                        res[i] = new DataValue((node as NodeReferenceType).IsAbstract, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.Symmetric && node is NodeReferenceType)
                    {
                        res[i] = new DataValue((node as NodeReferenceType).IsSymmetric, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.InverseName && node is NodeReferenceType)
                    {
                        res[i] = new DataValue((node as NodeReferenceType).InverseName, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.ContainsNoLoops && node is NodeView)
                    {
                        res[i] = new DataValue((node as NodeView).ContainsNoLoops, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.EventNotifier && node is NodeView)
                    {
                        res[i] = new DataValue((node as NodeView).EventNotifier, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.EventNotifier && node is NodeObject)
                    {
                        res[i] = new DataValue((node as NodeObject).EventNotifier, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.DataType && node is NodeVariable)
                    {
                        res[i] = new DataValue((node as NodeVariable).DataType, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.DataType && node is NodeVariableType)
                    {
                        res[i] = new DataValue((node as NodeVariableType).DataType, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.AccessLevel && node is NodeVariable)
                    {
                        res[i] = new DataValue((byte)(node as NodeVariable).AccessLevel, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.UserAccessLevel && node is NodeVariable)
                    {
                        res[i] = new DataValue((byte)(node as NodeVariable).UserAccessLevel, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.Historizing && node is NodeVariable)
                    {
                        res[i] = new DataValue((node as NodeVariable).IsHistorizing, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.MinimumSamplingInterval && node is NodeVariable)
                    {
                        res[i] = new DataValue((node as NodeVariable).MinimumResamplingInterval, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.Executable && node is NodeMethod)
                    {
                        res[i] = new DataValue((node as NodeMethod).IsExecutable, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.UserExecutable && node is NodeMethod)
                    {
                        res[i] = new DataValue((node as NodeMethod).IsUserExecutable, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.ValueRank && node is NodeVariable)
                    {
                        res[i] = new DataValue((Int32)0, StatusCode.Good);
                    }
                    else
                    {
                        // Trace.WriteLine($"Wrong attrib id: {(NodeAttribute)readValueIds[i].AttributeId}");
                        

                        res[i] = new DataValue(null, StatusCode.BadAttributeIdInvalid);
                    }
                }

                return res;
            }

            protected bool SessionHasPermissionToRead(object session, NodeId nodeId)
            {
                if (_AddressSpaceTable.TryGetValue(nodeId, out Node node))
                {
                    //node.Per
                }

                return true;
            }

          

        }
    }
}
