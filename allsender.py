import socket
import time
import logging
import traceback
from scapy.arch import get_if_list
from rich.table import Table
from rich import print, box
from base.sender import Sender
from base.parameter import Parameter
from base.sender_signal import post_set, pre_set
from base.signal import receiver
from base.exceptions import SetParameterException
logger = logging.getLogger("fuzz")
import struct


class SocksClientSender(Sender):
    """
    Socks发包器
    """

    _socket = None

    """信号函数消息订阅id"""
    __publisher_uid__ = "SocksClientSender"

    """本机网络接口列表"""
    iface_dict = {}

    def _parameters(self):
        """设置该发包器支持的运行参数"""
        parameters = dict(
            remote_ip=Parameter(
                name="remote_ip",  # 参数名称
                value="110.242.68.4",  # 默认值
                check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                check_error="ip地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="目标地址",  # 参数描述信息
                label="目标地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            remote_port=Parameter(
                name="remote_port",
                value=80,
                check="^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$",
                check_error="端口范围在(0-65535)",
                data_type="int",
                description="目标端口",
                label="目标端口",
                group="target",
            ),
            proxy_ip=Parameter(
                name="proxy_ip",  # 参数名称
                value="::1",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                check_error="ip地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="代理地址",  # 参数描述信息
                label="代理地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            proxy_port=Parameter(
                name="proxy_port",
                value=1080,
                check="^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$",
                check_error="端口范围在(0-65535)",
                data_type="int",
                description="代理端口",
                label="代理端口",
                group="target",
            ),
            interface=Parameter(
                name="interface",
                value="lo",
                data_type="string",
                description="先使用interface命令获取网络接口列表，然后使用select命令根据编号或名称选择网络接口",
                label="网络接口",
                element_type="select",
                # 表单元素类型: input-输入框；textarea：文本域；select：下拉框；multiple-select：多选下拉框；radio：单选框；checkbox；多选框；button-按钮
                use=[{"command": "select {}"}],  # 前端设置完该参数后调用的命令
                origin={
                    "command": ["interface"],
                    "is_sync": True,
                },  # 参数可选项的获取来源，字典，结构为：{"command": ["scan"], "is_sync": True}, is_sync=True表示从方法返回值获取，为False表示从消息队列异步获取
            ),
            username=Parameter(
                name="username",
                value="USERNAME",
                data_type="string",
                description="认证用户名",
                label="用户名",
            ),
            password=Parameter(
                name="password",
                value="swift123",
                data_type="string",
                description="认证密码",
                label="密码",
            ),
            loop=Parameter(
                name="loop",
                value=1,
                data_type="int",
                description="每个用例执行状态机流程的循环次数",
                label="循环次数",
            ),
            timeout=Parameter(
                name="timeout",
                value=2,
                data_type="int",
                description="用例预检的超时时间",
                label="超时时间",
            ),
            count=Parameter(
                name="count",
                value=1,
                data_type="int",
                description="每个用例连续发送次数",
                label="发送次数",
            ),
            interval=Parameter(
                name="interval",
                value=0,
                data_type="float",
                description="发送间隔",
                label="发送间隔",
            ),
        )
        return parameters

    def do_interface(self, opt):
        """获取本机网络接口列表，在命令行模式中输入interface命令即可"""
        self.iface_dict = {}
        iface_result = []
        iface_list = get_if_list()
        table = Table(
            show_header=True, header_style="bright_green", box=box.DOUBLE_EDGE
        )
        table.add_column("INDEX", justify="center")
        table.add_column("网络接口名称", justify="center")
        for index, iface in enumerate(iface_list):
            self.iface_dict[index + 1] = iface
            table.add_row(*(str(index + 1), iface_list[index]), style="blue")
            iface_result.append(dict(label=str(index), value=iface))
        print(table)
        return iface_result

    def do_select(self, index):
        """根据do_interface获取到的本机网络接口列表，通过索引或者网络接口名称设置interface参数的值"""
        self.do_set(f"interface {index}")

    @receiver(signal=pre_set, publishers=__publisher_uid__)
    def pre_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法代码之前自动执行，校验设置的网络接口是否为本机的网络接口，如果不是则抛出SetParameterException异常
        :param signal:
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) not in self.iface_dict.keys():
                    raise SetParameterException(
                        f"Can't Find Interface By Index '{interface}'"
                    )
            else:
                if interface not in self.iface_dict.values():
                    raise SetParameterException(f"Can't Find Interface '{interface}'")

    @receiver(signal=post_set, publishers=__publisher_uid__)
    def post_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法之后自动执行，将按索引设置网络接口转成按名称设置
        :param signal:
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) in self.iface_dict.keys():
                    interface = self.iface_dict.get(int(interface))
                    self.do_set(f"interface {interface}")

    def connect(self):
        """
        打开socket连接，执行状态机'输入'或'输出'动作之前调用，每个发包器必须实现connect方法
        """
        if self.is_connected:
            return
        socket.setdefaulttimeout(self.timeout)
        self._socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(self.interface, "utf-8"))
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 ** 16)
        self._socket.connect((self.proxy_ip, self.proxy_port))
        self.is_connected = True
        logger.info("打开socket连接")

    def close(self):
        """
        关闭socket连接，每次状态机流程执行完成后调用，，每个发包器必须实现close方法
        """
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception as e:
                logger.error(f"Error closing socket: {e}")
            finally:
                self._socket = None
                self.is_connected = False
                logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法关闭socket连接！")
        else:
            logger.info("Socket is already closed.")
        """
        if self._socket is not None:
            self._socket.close()
            self._socket = None
            self.is_connected = False
            logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法关闭socket连接！")
        """    
    def send(self, data: bytes):
        """
        发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法
        :param data: Data to send
        """
        try:
            print(data,'A'*100)
            self._socket.send(data)
        except ConnectionResetError:
            logger.error(traceback.format_exc())

    def receive(self, size=None):
        """
        接收数据包，执行状态机'输入'动作时调用，每个发包器必须实现receive方法
        Receive data
        :param size:
        :return:
        """
        if size is not None:
            return self._socket.recv(size)
        else:
            self._socket.setblocking(0)
            timeout = 0.5
            start_time = time.time()
            ret = b""
            try:
                while True:
                    if len(ret) > 0 or time.time() - start_time > timeout:
                        break
                    try:
                        recv_packet = self._socket.recv(4096)
                        """
                        logger.info(recv_packet)
                        """
                        ret += recv_packet
                        if recv_packet:
                            break
                    except BlockingIOError as e:
                        pass
                    except socket.error as e:
                        if (
                                str(e).find(
                                    "The socket operation could not complete without blocking"
                                )
                                == -1
                        ):
                            raise
            except:
                logger.error(traceback.format_exc())
            finally:
                self._socket.setblocking(1)
            return ret

class ClientTimeoutErrorr(Exception):
    def __init__(self, message="客户端连接超时"):
        super().__init__(message)

class SocksServerSender(Sender):
    """
    Socks发包器
    """

    _socket = None

    """信号函数消息订阅id"""
    __publisher_uid__ = "SocksServerSender"

    """本机网络接口列表"""
    iface_dict = {}

    def _parameters(self):
        """设置该发包器支持的运行参数"""
        parameters = dict(
            remote_ip=Parameter(
                name="remote_ip",  # 参数名称
                value="110.242.68.4",  # 默认值
                check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                check_error="ip地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="目标地址",  # 参数描述信息
                label="目标地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            remote_port=Parameter(
                name="remote_port",
                value=80,
                check="^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$",
                check_error="端口范围在(0-65535)",
                data_type="int",
                description="目标端口",
                label="目标端口",
                group="target",
            ),
            proxy_ip=Parameter(
                name="proxy_ip",  # 参数名称
                value="127.0.0.1",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                check_error="ip地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="代理地址",  # 参数描述信息
                label="代理地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            proxy_port=Parameter(
                name="proxy_port",
                value=1080,
                check="^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$",
                check_error="端口范围在(0-65535)",
                data_type="int",
                description="代理端口",
                label="代理端口",
                group="target",
            ),
            interface=Parameter(
                name="interface",
                value="lo",
                data_type="string",
                description="先使用interface命令获取网络接口列表，然后使用select命令根据编号或名称选择网络接口",
                label="网络接口",
                element_type="select",
                # 表单元素类型: input-输入框；textarea：文本域；select：下拉框；multiple-select：多选下拉框；radio：单选框；checkbox；多选框；button-按钮
                use=[{"command": "select {}"}],  # 前端设置完该参数后调用的命令
                origin={
                    "command": ["interface"],
                    "is_sync": True,
                },  # 参数可选项的获取来源，字典，结构为：{"command": ["scan"], "is_sync": True}, is_sync=True表示从方法返回值获取，为False表示从消息队列异步获取
            ),
            username=Parameter(
                name="username",
                value="USERNAME",
                data_type="string",
                description="认证用户名",
                label="用户名",
            ),
            password=Parameter(
                name="password",
                value="swift123",
                data_type="string",
                description="认证密码",
                label="密码",
            ),
            timeout=Parameter(
                name="timeout",
                value=10,
                data_type="int",
                description="客户端用例预检的超时时间",
                label="客户端超时时间",
            ),
            loop=Parameter(
                name="loop",
                value=1,
                data_type="int",
                description="每个用例执行状态机流程的循环次数",
                label="循环次数",
            ),
            count=Parameter(
                name="count",
                value=1,
                data_type="int",
                description="每个用例连续发送次数",
                label="发送次数",
            ),
            interval=Parameter(
                name="interval",
                value=0,
                data_type="float",
                description="发送间隔",
                label="发送间隔",
            ),
        )
        return parameters

    def do_interface(self, opt):
        """获取本机网络接口列表，在命令行模式中输入interface命令即可"""
        self.iface_dict = {}
        iface_result = []
        iface_list = get_if_list()
        table = Table(
            show_header=True, header_style="bright_green", box=box.DOUBLE_EDGE
        )
        table.add_column("INDEX", justify="center")
        table.add_column("网络接口名称", justify="center")
        for index, iface in enumerate(iface_list):
            self.iface_dict[index + 1] = iface
            table.add_row(*(str(index + 1), iface_list[index]), style="blue")
            iface_result.append(dict(label=str(index), value=iface))
        print(table)
        return iface_result

    def do_select(self, index):
        """根据do_interface获取到的本机网络接口列表，通过索引或者网络接口名称设置interface参数的值"""
        self.do_set(f"interface {index}")

    @receiver(signal=pre_set, publishers=__publisher_uid__)
    def pre_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法代码之前自动执行，校验设置的网络接口是否为本机的网络接口，如果不是则抛出SetParameterException异常
        :param signal:
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) not in self.iface_dict.keys():
                    raise SetParameterException(
                        f"Can't Find Interface By Index '{interface}'"
                    )
            else:
                if interface not in self.iface_dict.values():
                    raise SetParameterException(f"Can't Find Interface '{interface}'")

    @receiver(signal=post_set, publishers=__publisher_uid__)
    def post_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法之后自动执行，将按索引设置网络接口转成按名称设置
        :param signal:
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) in self.iface_dict.keys():
                    interface = self.iface_dict.get(int(interface))
                    self.do_set(f"interface {interface}")
    
    def connect(self):
        """
        等待并接受客户端连接，执行状态机'输入'或'输出'动作之前调用，
        """
        if self.is_connected:
            return
        socket.setdefaulttimeout(self.timeout)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(self.interface, "utf-8"))
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 ** 16)
        self._socket.bind((self.proxy_ip, self.proxy_port))
        self._socket.listen(5)
        
        try:
            self.client_socket, client_address = self._socket.accept()
            logger.info(f"客户端{client_address}连接成功")
            self.is_connect = True
        except TimeoutError:
            logger.error('客户端连接超时')
            raise ClientTimeoutErrorr
        except socket.error as e:
            logger.error(f"发生 socket 错误: {e}")
        except Exception as e:
            logger.error(f"发生未知错误: {e}")
        
        

    
    """
    def connect(self):
                
        打开socket连接，执行状态机'输入'或'输出'动作之前调用，每个发包器必须实现connect方法
        
        if self.is_connected:
            return
        socket.setdefaulttimeout(2)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(self.interface, "utf-8"))
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 ** 16)
        self._socket.connect((self.proxy_ip, self.proxy_port))
        self.is_connected = True
        logger.info("打开socket连接")
    """    
    
    def close(self):
        """
        关闭socket连接，每次状态机流程执行完成后调用，，每个发包器必须实现close方法
        """
        """
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception as e:
                logger.error(f"Error closing socket: {e}")
            finally:
                self._socket = None
                self.is_connected = False
                logger.info("关闭socket连接")
        else:
            logger.info("Socket is already closed.")
        """
        if self._socket is not None:
            self._socket.close()
            self._socket = None
            self.is_connected = False
            logger.info("关闭socket连接")
        

    
    def send(self, data: bytes):
        """
        发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法
        :param data: Data to send
        """
        self._socket.settimeout(20)
        try:
            print(data,'A'*100)
            print('发送中.......')
            self.client_socket.send(data)
            print('发送成功')
        except ConnectionResetError:
            logger.error(traceback.format_exc())
    
    def receive(self, size=None):
        """
        接收数据包，执行状态机'输入'动作时调用，每个发包器必须实现receive方法
        Receive data
        :param size:
        :return:
        """
        if size is not None:
            return self._socket.recv(size)
        else:
            self._socket.setblocking(0)
            timeout = 0.5
            start_time = time.time()
            ret = b""
            try:
                while True:
                    if len(ret) > 0 or time.time() - start_time > timeout:
                        break
                    try:
                        recv_packet = self._socket.recv(4096)
                        """
                        logger.info(recv_packet)
                        """
                        ret += recv_packet
                        if recv_packet:
                            break
                    except BlockingIOError as e:
                        pass
                    except socket.error as e:
                        if (
                                str(e).find(
                                    "The socket operation could not complete without blocking"
                                )
                                == -1
                        ):
                            raise
            except:
                logger.error(traceback.format_exc())
            finally:
                self._socket.setblocking(1)
            return ret

class SctpSender(Sender):
    """
    Socks发包器
    """

    _socket = None

    """信号函数消息订阅id"""
    __publisher_uid__ = "Socks5Sender"

    """本机网络接口列表"""
    iface_dict = {}

    def _parameters(self):
        """设置该发包器支持的运行参数"""
        parameters = dict(
            dst_ip=Parameter(
                name="destination_ip",  # 参数名称
                value="127.0.0.1",  # 默认值
                check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                check_error="ip地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="目标地址",  # 参数描述信息
                label="目标地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            dst_port=Parameter(
                name="destination_port",
                value=2904,
                check="^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$",
                check_error="端口范围在(0-65535)",
                data_type="int",
                description="目标端口",
                label="目标端口",
                group="target",
            ),
            src_ip=Parameter(
                name="source_ip",  # 参数名称
                value="127.0.0.1",  # 默认值
                check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                check_error="ip地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="源地址",  # 参数描述信息
                label="源地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            src_port=Parameter(
                name="source_port",
                value=45522,
                check="^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$",
                check_error="端口范围在(0-65535)",
                data_type="int",
                description="源端口",
                label="源端口",
                group="target",
            ),
            interface=Parameter(
                name="interface",
                value="lo",
                data_type="string",
                description="先使用interface命令获取网络接口列表，然后使用select命令根据编号或名称选择网络接口",
                label="网络接口",
                element_type="select",
                # 表单元素类型: input-输入框；textarea：文本域；select：下拉框；multiple-select：多选下拉框；radio：单选框；checkbox；多选框；button-按钮
                use=[{"command": "select {}"}],  # 前端设置完该参数后调用的命令
                origin={
                    "command": ["interface"],
                    "is_sync": True,
                },  # 参数可选项的获取来源，字典，结构为：{"command": ["scan"], "is_sync": True}, is_sync=True表示从方法返回值获取，为False表示从消息队列异步获取
            ),
            loop=Parameter(
                name="loop",
                value=1,
                data_type="int",
                description="每个用例执行状态机流程的循环次数",
                label="循环次数",
            ),
            count=Parameter(
                name="count",
                value=1,
                data_type="int",
                description="每个用例连续发送次数",
                label="发送次数",
            ),
            interval=Parameter(
                name="interval",
                value=0,
                data_type="float",
                description="发送间隔",
                label="发送间隔",
            ),
        )
        return parameters

    def do_interface(self, opt):
        """获取本机网络接口列表，在命令行模式中输入interface命令即可"""
        self.iface_dict = {}
        iface_result = []
        iface_list = get_if_list()
        table = Table(
            show_header=True, header_style="bright_green", box=box.DOUBLE_EDGE
        )
        table.add_column("INDEX", justify="center")
        table.add_column("网络接口名称", justify="center")
        for index, iface in enumerate(iface_list):
            self.iface_dict[index + 1] = iface
            table.add_row(*(str(index + 1), iface_list[index]), style="blue")
            iface_result.append(dict(label=str(index), value=iface))
        print(table)
        return iface_result

    def do_select(self, index):
        """根据do_interface获取到的本机网络接口列表，通过索引或者网络接口名称设置interface参数的值"""
        self.do_set(f"interface {index}")

    @receiver(signal=pre_set, publishers=__publisher_uid__)
    def pre_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法代码之前自动执行，校验设置的网络接口是否为本机的网络接口，如果不是则抛出SetParameterException异常
        :param signal:
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) not in self.iface_dict.keys():
                    raise SetParameterException(
                        f"Can't Find Interface By Index '{interface}'"
                    )
            else:
                if interface not in self.iface_dict.values():
                    raise SetParameterException(f"Can't Find Interface '{interface}'")

    @receiver(signal=post_set, publishers=__publisher_uid__)
    def post_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法之后自动执行，将按索引设置网络接口转成按名称设置
        :param signal:
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) in self.iface_dict.keys():
                    interface = self.iface_dict.get(int(interface))
                    self.do_set(f"interface {interface}")

    def connect(self):
        """
        打开socket连接，执行状态机'输入'或'输出'动作之前调用，每个发包器必须实现connect方法
        """
        if self.is_connected:
            return
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 ** 16)
        logger.info("原始套接字创建成功")

    def close(self):
        """
        关闭socket连接，每次状态机流程执行完成后调用，，每个发包器必须实现close方法
        """
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception as e:
                logger.error(f"Error closing socket: {e}")
            finally:
                self._socket = None
                self.is_connected = False
                logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法关闭socket连接！")
        else:
            logger.info("Socket is already closed.")
        """
        if self._socket is not None:
            self._socket.close()
            self._socket = None
            self.is_connected = False
            logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法关闭socket连接！")
        """    
    def send(self, data: bytes):
        """
        发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法
        :param data: Data to send
        """
        self._socket.settimeout(10)
        try:
            print(data,'A'*100)
            self._socket.sendto(data, (self.dst_ip, self.dst_port))
        except ConnectionResetError:
            logger.error(traceback.format_exc())

    def receive(self, size=None):
        """
        接收数据包，执行状态机'输入'动作时调用，每个发包器必须实现receive方法
        Receive data
        :param size:
        :return:
        """
        if size is not None:
            return self._socket.recv(size)
        else:
            self._socket.setblocking(0)
            timeout = 0.5
            start_time = time.time()
            ret = b""
            try:
                while True:
                    if len(ret) > 0 or time.time() - start_time > timeout:
                        break
                    try:
                        recv_packet = self._socket.recv(4096)
                        """
                        logger.info(recv_packet)
                        """
                        ret += recv_packet
                        if recv_packet:
                            break
                    except BlockingIOError as e:
                        pass
                    except socket.error as e:
                        if (
                                str(e).find(
                                    "The socket operation could not complete without blocking"
                                )
                                == -1
                        ):
                            raise
            except:
                logger.error(traceback.format_exc())
            finally:
                self._socket.setblocking(1)
            return ret

class PppoeSender(Sender):
    """
    PPPoE发包器
    """

    _socket = None

    """信号函数消息订阅id"""
    __publisher_uid__ = "PppoeSender"

    """本机网络接口列表"""
    iface_dict = {}

    def _parameters(self):
        """设置该发包器支持的运行参数"""
        parameters = dict(
            destination_address=Parameter(
                name="destination_address",  # 参数名称
                value="00:00:00:00:00:00",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                check_error="mac地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="目标地址",  # 参数描述信息
                label="目标地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),

            source_address=Parameter(
                name="source_address",  # 参数名称
                value="cc:96:e5:15:cb:cf",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                check_error="mac地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="源地址",  # 参数描述信息
                label="源地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),

            interface=Parameter(
                name="interface",
                value="lo",
                data_type="string",
                description="先使用interface命令获取网络接口列表，然后使用select命令根据编号或名称选择网络接口",
                label="网络接口",
                element_type="select",
                # 表单元素类型: input-输入框；textarea：文本域；select：下拉框；multiple-select：多选下拉框；radio：单选框；checkbox；多选框；button-按钮
                use=[{"command": "select {}"}],  # 前端设置完该参数后调用的命令
                origin={
                    "command": ["interface"],
                    "is_sync": True,
                },  # 参数可选项的获取来源，字典，结构为：{"command": ["scan"], "is_sync": True}, is_sync=True表示从方法返回值获取，为False表示从消息队列异步获取
            ),
            loop=Parameter(
                name="loop",
                value=1,
                data_type="int",
                description="每个用例执行状态机流程的循环次数",
                label="循环次数",
            ),
            count=Parameter(
                name="count",
                value=1,
                data_type="int",
                description="每个用例连续发送次数",
                label="发送次数",
            ),
            interval=Parameter(
                name="interval",
                value=0,
                data_type="float",
                description="发送间隔",
                label="发送间隔",
            ),
        )
        return parameters

    def do_interface(self, opt):
        """获取本机网络接口列表，在命令行模式中输入interface命令即可"""
        self.iface_dict = {}
        iface_result = []
        iface_list = get_if_list()
        table = Table(
            show_header=True, header_style="bright_green", box=box.DOUBLE_EDGE
        )
        table.add_column("INDEX", justify="center")
        table.add_column("网络接口名称", justify="center")
        for index, iface in enumerate(iface_list):
            self.iface_dict[index + 1] = iface
            table.add_row(*(str(index + 1), iface_list[index]), style="blue")
            iface_result.append(dict(label=str(index), value=iface))
        print(table)
        return iface_result

    def do_select(self, index):
        """根据do_interface获取到的本机网络接口列表，通过索引或者网络接口名称设置interface参数的值"""
        self.do_set(f"interface {index}")

    @receiver(signal=pre_set, publishers=__publisher_uid__)
    def pre_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法代码之前自动执行，校验设置的网络接口是否为本机的网络接口，如果不是则抛出SetParameterException异常
        :param signal:
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) not in self.iface_dict.keys():
                    raise SetParameterException(
                        f"Can't Find Interface By Index '{interface}'"
                    )
            else:
                if interface not in self.iface_dict.values():
                    raise SetParameterException(f"Can't Find Interface '{interface}'")

    @receiver(signal=post_set, publishers=__publisher_uid__)
    def post_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法之后自动执行，将按索引设置网络接口转成按名称设置
        :param signal:dst_adds
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) in self.iface_dict.keys():
                    interface = self.iface_dict.get(int(interface))
                    self.do_set(f"interface {interface}")

    def connect(self):
        """
        打开socket连接，执行状态机'输入'或'输出'动作之前调用，每个发包器必须实现connect方法
        """
        logger.info(self.parameters)
        if self.is_connected:
            return
        self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self._socket.bind((self.interface, 0))
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 ** 16)
        self.count = 0
        if self.count == 0:
            self._socket_recv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            print(self.count)
        logger.info("原始套接字创建成功")

    def close(self):
        """
        关闭socket连接，每次状态机流程执行完成后调用，，每个发包器必须实现close方法
        """
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception as e:
                logger.error(f"Error closing socket: {e}")
            finally:
                self._socket = None
                self.is_connected = False
                logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现close方法关闭socket连接！")
        else:
            logger.info("Socket is already closed.")
        
        if self.count != 1:    
            if self._socket_recv is not None:
                try:
                    self._socket_recv.close()
                except Exception as e:
                    logger.error(f"Error closing socket: {e}")
                finally:
                    self._socket_recv = None
                    self.is_connected = False
                    logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现close方法关闭socket连接！")
            else:
                logger.info("Socket is already closed.")
        """
        if self._socket is not None:
            self._socket.close()
            self._socket = None
            self.is_connected = False
            logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法关闭socket连接！")
        """    
    def send(self, data: bytes):
        """
        发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法
        :param data: Data to send
        """
        # print(self.parameters)
        # print(self.dst_adds)
        # print(self.src_adds)
        # print(data)
        self._socket.settimeout(10)
        try:
            #print(data,'A'*100)
            self._socket.sendto(data, (self.interface, 0))
            
        except ConnectionResetError:
            logger.error(traceback.format_exc())

 
        
    def receive(self, size=None):
        """
        接收数据包，执行状态机'输入'动作时调用， 每个发包器必须实现receive方法
        Receive data
        :param size:
        :return:
        """
        print(self.count)
        if self.count == 0:
            pass
        else:
            self._socket_recv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        if size is not None:
            return self._socket_recv.recv(size)
        else:
            self._socket_recv.setblocking(0)
            timeout = 5
            start_time = time.time()
            ret = b""
            try:
                while True:
                    if len(ret) > 0 or time.time() - start_time > timeout:
                        break
                    try:
                        recv_packet = self._socket_recv.recv(4096)
                        """
                        logger.info(recv_packet)
                        """
                        # logger.info(f"shoudaodebao: {recv_packet}")
                        # byte_1,byte_2,byte_3,byte_4,byte_5,byte_6 = struct.unpack('BBBBBB',recv_packet[0:6])
                        # mac_address = (byte_1 << 40 ) | (byte_2 << 32) | (byte_3 << 24) | (byte_4 << 16) | (byte_5 << 8) | byte_6
                        byte_13 = recv_packet[12]
                        byte_14 = recv_packet[13]
                        ethernet_type = (byte_13 << 8) | byte_14
                        discovery_code = recv_packet[15]
                        byte_21 = recv_packet[20]
                        byte_22 = recv_packet[21]
                        protocol = (byte_21 << 8) | byte_22
                        code = recv_packet[22]
                        # print(hex(ethernet_type), hex(discovery_code), hex(protocol), hex(code),'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB')
                        
                        
                        if (ethernet_type == 0x8863 and discovery_code == 0x07):
                            ret += recv_packet
                        elif (ethernet_type == 0x8863 and discovery_code == 0x65):
                            ret += recv_packet 
                        elif (ethernet_type == 0x8864 and protocol == 0xc223 and code == 1):
                            ret += recv_packet
                        elif (ethernet_type == 0x8864 and protocol == 0xc021 and code == 1):
                            ret += recv_packet
                        elif (ethernet_type == 0x8864 and protocol == 0x8021 and code == 1):
                            ret += recv_packet
                        # print('b'*100)
                        
                        # print(ret)
                        # if recv_packet:
                        #     print('recv_packet in not empty')
                        #     break
                    except BlockingIOError as e:
                        pass
                    except socket.error as e:
                        if (
                                str(e).find(
                                    "The socket operation could not complete without blocking"
                                )
                                == -1
                        ):
                            raise
            except:
                logger.error(traceback.format_exc())
            finally:
                self._socket_recv.setblocking(1)
            self.count += 1
            self._socket_recv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            print(ret,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
            return ret
        
class ISISSender(Sender):
    """
    ISIS发包器
    """

    _socket = None

    """信号函数消息订阅id"""
    __publisher_uid__ = "ISISSender"

    """本机网络接口列表"""
    iface_dict = {}

    def _parameters(self):
        """设置该发包器支持的运行参数"""
        parameters = dict(
            destination_address_L1=Parameter(
                name="destination_address_L1",  # 参数名称
                value="01:80:c2:00:00:14",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                #check_error="mac地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="目标地址",  # 参数描述信息
                label="目标地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            destination_address_L2=Parameter(
                name="destination_address_L2",  # 参数名称
                value="01:80:c2:00:00:15",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                #check_error="mac地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="目标地址",  # 参数描述信息
                label="目标地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            destination_address_P2P=Parameter(
                name="destination_address_P2P",  # 参数名称
                value="09:00:2b:00:00:05",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                #check_error="mac地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="目标地址",  # 参数描述信息
                label="目标地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            source_address=Parameter(
                name="source_address",  # 参数名称
                value="02:42:c0:a8:02:64",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                #check_error="mac地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="源地址",  # 参数描述信息
                label="源地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),

            interface=Parameter(
                name="interface",
                value="br-9c5b873773fa",
                data_type="string",
                description="先使用interface命令获取网络接口列表，然后使用select命令根据编号或名称选择网络接口",
                label="网络接口",
                element_type="select",
                # 表单元素类型: input-输入框；textarea：文本域；select：下拉框；multiple-select：多选下拉框；radio：单选框；checkbox；多选框；button-按钮
                use=[{"command": "select {}"}],  # 前端设置完该参数后调用的命令
                origin={
                    "command": ["interface"],
                    "is_sync": True,
                },  # 参数可选项的获取来源，字典，结构为：{"command": ["scan"], "is_sync": True}, is_sync=True表示从方法返回值获取，为False表示从消息队列异步获取
            ),
            loop=Parameter(
                name="loop",
                value=1,
                data_type="int",
                description="每个用例执行状态机流程的循环次数",
                label="循环次数",
            ),
            count=Parameter(
                name="count",
                value=1,
                data_type="int",
                description="每个用例连续发送次数",
                label="发送次数",
            ),
            interval=Parameter(
                name="interval",
                value=0,
                data_type="float",
                description="发送间隔",
                label="发送间隔",
            ),
        )
        return parameters

    def do_interface(self, opt):
        """获取本机网络接口列表，在命令行模式中输入interface命令即可"""
        self.iface_dict = {}
        iface_result = []
        iface_list = get_if_list()
        table = Table(
            show_header=True, header_style="bright_green", box=box.DOUBLE_EDGE
        )
        table.add_column("INDEX", justify="center")
        table.add_column("网络接口名称", justify="center")
        for index, iface in enumerate(iface_list):
            self.iface_dict[index + 1] = iface
            table.add_row(*(str(index + 1), iface_list[index]), style="blue")
            iface_result.append(dict(label=str(index), value=iface))
        print(table)
        return iface_result

    def do_select(self, index):
        """根据do_interface获取到的本机网络接口列表，通过索引或者网络接口名称设置interface参数的值"""
        self.do_set(f"interface {index}")

    @receiver(signal=pre_set, publishers=__publisher_uid__)
    def pre_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法代码之前自动执行，校验设置的网络接口是否为本机的网络接口，如果不是则抛出SetParameterException异常
        :param signal:
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) not in self.iface_dict.keys():
                    raise SetParameterException(
                        f"Can't Find Interface By Index '{interface}'"
                    )
            else:
                if interface not in self.iface_dict.values():
                    raise SetParameterException(f"Can't Find Interface '{interface}'")

    @receiver(signal=post_set, publishers=__publisher_uid__)
    def post_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法之后自动执行，将按索引设置网络接口转成按名称设置
        :param signal:dst_adds
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) in self.iface_dict.keys():
                    interface = self.iface_dict.get(int(interface))
                    self.do_set(f"interface {interface}")

    def connect(self):
        """
        打开socket连接，执行状态机'输入'或'输出'动作之前调用，每个发包器必须实现connect方法
        """
        logger.info(self.parameters)
        if self.is_connected:
            return
        self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self._socket.bind((self.interface, 0))
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 ** 16)
        self.count = 0
        # if self.count == 0:
        #     self._socket_recv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        #     print(self.count)
        logger.info("原始套接字创建成功")

    def close(self):
        """
        关闭socket连接，每次状态机流程执行完成后调用，，每个发包器必须实现close方法
        """
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception as e:
                logger.error(f"Error closing socket: {e}")
            finally:
                self._socket = None
                self.is_connected = False
                logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现close方法关闭socket连接！")
        else:
            logger.info("Socket is already closed.")
        

        if self.count != 1:  
            if self._socket_recv is not None:
                try:
                    self._socket_recv.close()
                except Exception as e:
                    logger.error(f"Error closing socket: {e}")
                finally:
                    self._socket_recv = None
                    self.is_connected = False
                    logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现close方法关闭socket连接！")
            else:
                logger.info("Socket is already closed.")
        """
        if self._socket is not None:
            self._socket.close()
            self._socket = None
            self.is_connected = False
            logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法关闭socket连接！")
        """    
    def send(self, data: bytes):
        """
        发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法
        :param data: Data to send
        """
        # print(self.parameters)
        # print(self.dst_adds)
        # print(self.src_adds)
        # print(data)
        self._socket.settimeout(10)
        try:
            #print(data,'A'*100)
            self._socket.sendto(data, (self.interface, 0))
            
        except ConnectionResetError:
            logger.error(traceback.format_exc())

 
        
    def receive(self, size=None):
        """
        接收数据包，执行状态机'输入'动作时调用， 每个发包器必须实现receive方法
        Receive data
        :param size:
        :return:
        """
        # print(self.count)
        # if self.count == 0:
        #     pass
        # else:
        self._socket_recv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        if size is not None:
            return self._socket_recv.recv(size)
        else:
            self._socket_recv.setblocking(0)
            timeout = 5
            start_time = time.time()
            ret = b""
            try:
                while True:
                    if len(ret) > 0 or time.time() - start_time > timeout:
                        break
                    try:
                        recv_packet = self._socket_recv.recv(4096)
                        """
                        logger.info(recv_packet)
                        """
                        byte_18 = recv_packet[17]
                        protocol_id = byte_18
                        byte_54 = recv_packet[53]
                        neighbor = byte_54
                        
                        if protocol_id == 0x83 and neighbor == 0x06:
                            ret += recv_packet
                    
                        # ret += recv_packet
                    except BlockingIOError as e:
                        pass
                    except socket.error as e:
                        if (
                                str(e).find(
                                    "The socket operation could not complete without blocking"
                                )
                                == -1
                        ):
                            raise
            except:
                logger.error(traceback.format_exc())
            finally:
                self._socket_recv.setblocking(1)
            self.count += 1
            self._socket_recv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            print(ret,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
            return ret
        
class VXLANSender(Sender):
    """
    VXLAN发包器
    """

    _socket = None

    """信号函数消息订阅id"""
    __publisher_uid__ = "VXLANSender"

    """本机网络接口列表"""
    iface_dict = {}

    def _parameters(self):
        """设置该发包器支持的运行参数"""
        parameters = dict(
            destination_address_L1=Parameter(
                name="destination_address_L1",  # 参数名称
                value="01:80:c2:00:00:14",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                #check_error="mac地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="目标地址",  # 参数描述信息
                label="目标地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),
            source_address=Parameter(
                name="source_address",  # 参数名称
                value="02:42:c0:a8:02:64",  # 默认值
                #check="^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$",  # 参数值格式校验正则表达式
                #check_error="mac地址格式不正确",  # 正则表达式校验未通过时前端展示的错误消息
                data_type="string",  # 数据类型：string、int、float、bool
                description="源地址",  # 参数描述信息
                label="源地址",  # 参数在前端的展示名称
                group="target",  # 参数分组：group值为target的时候表示该参数是测试目标
            ),

            interface=Parameter(
                name="interface",
                value="br-9c5b873773fa",
                data_type="string",
                description="先使用interface命令获取网络接口列表，然后使用select命令根据编号或名称选择网络接口",
                label="网络接口",
                element_type="select",
                # 表单元素类型: input-输入框；textarea：文本域；select：下拉框；multiple-select：多选下拉框；radio：单选框；checkbox；多选框；button-按钮
                use=[{"command": "select {}"}],  # 前端设置完该参数后调用的命令
                origin={
                    "command": ["interface"],
                    "is_sync": True,
                },  # 参数可选项的获取来源，字典，结构为：{"command": ["scan"], "is_sync": True}, is_sync=True表示从方法返回值获取，为False表示从消息队列异步获取
            ),
            loop=Parameter(
                name="loop",
                value=1,
                data_type="int",
                description="每个用例执行状态机流程的循环次数",
                label="循环次数",
            ),
            count=Parameter(
                name="count",
                value=1,
                data_type="int",
                description="每个用例连续发送次数",
                label="发送次数",
            ),
            interval=Parameter(
                name="interval",
                value=0,
                data_type="float",
                description="发送间隔",
                label="发送间隔",
            ),
        )
        return parameters

    def do_interface(self, opt):
        """获取本机网络接口列表，在命令行模式中输入interface命令即可"""
        self.iface_dict = {}
        iface_result = []
        iface_list = get_if_list()
        table = Table(
            show_header=True, header_style="bright_green", box=box.DOUBLE_EDGE
        )
        table.add_column("INDEX", justify="center")
        table.add_column("网络接口名称", justify="center")
        for index, iface in enumerate(iface_list):
            self.iface_dict[index + 1] = iface
            table.add_row(*(str(index + 1), iface_list[index]), style="blue")
            iface_result.append(dict(label=str(index), value=iface))
        print(table)
        return iface_result

    def do_select(self, index):
        """根据do_interface获取到的本机网络接口列表，通过索引或者网络接口名称设置interface参数的值"""
        self.do_set(f"interface {index}")

    @receiver(signal=pre_set, publishers=__publisher_uid__)
    def pre_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法代码之前自动执行，校验设置的网络接口是否为本机的网络接口，如果不是则抛出SetParameterException异常
        :param signal:
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) not in self.iface_dict.keys():
                    raise SetParameterException(
                        f"Can't Find Interface By Index '{interface}'"
                    )
            else:
                if interface not in self.iface_dict.values():
                    raise SetParameterException(f"Can't Find Interface '{interface}'")

    @receiver(signal=post_set, publishers=__publisher_uid__)
    def post_set_interface(self, signal, opt):
        """
        do_set方法信号，在执行do_set方法之后自动执行，将按索引设置网络接口转成按名称设置
        :param signal:dst_adds
        :param opt:
        :return:
        """
        if opt.name == "interface":
            interface = opt.value
            if interface.isdigit():
                if not self.iface_dict:
                    self.do_interface("")
                if int(interface) in self.iface_dict.keys():
                    interface = self.iface_dict.get(int(interface))
                    self.do_set(f"interface {interface}")

    def connect(self):
        """
        打开socket连接，执行状态机'输入'或'输出'动作之前调用，每个发包器必须实现connect方法
        """
        logger.info(self.parameters)
        if self.is_connected:
            return
        self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self._socket.bind((self.interface, 0))
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 ** 16)
        self.count = 0
        # if self.count == 0:
        #     self._socket_recv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        #     print(self.count)
        logger.info("原始套接字创建成功")

    def close(self):
        """
        关闭socket连接，每次状态机流程执行完成后调用，，每个发包器必须实现close方法
        """
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception as e:
                logger.error(f"Error closing socket: {e}")
            finally:
                self._socket = None
                self.is_connected = False
                logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现close方法关闭socket连接！")
        else:
            logger.info("Socket is already closed.")
        

        # if self.count != 1:  
        #     if self._socket_recv is not None:
        #         try:
        #             self._socket_recv.close()
        #         except Exception as e:
        #             logger.error(f"Error closing socket: {e}")
        #         finally:
        #             self._socket_recv = None
        #             self.is_connected = False
        #             logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现close方法关闭socket连接！")
        #     else:
        #         logger.info("Socket is already closed.")
        """
        if self._socket is not None:
            self._socket.close()
            self._socket = None
            self.is_connected = False
            logger.info("发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法关闭socket连接！")
        """    
    def send(self, data: bytes):
        """
        发送数据包，执行状态机'输出'动作时调用，每个发包器必须实现send方法
        :param data: Data to send
        """
        # print(self.parameters)
        # print(self.dst_adds)
        # print(self.src_adds)
        # print(data)
        self._socket.settimeout(10)
        try:
            #print(data,'A'*100)
            self._socket.sendto(data, (self.interface, 0))
            
        except ConnectionResetError:
            logger.error(traceback.format_exc())

 
        
    def receive(self, size=None):
        """
        接收数据包，执行状态机'输入'动作时调用， 每个发包器必须实现receive方法
        Receive data
        :param size:
        :return:
        """
        # print(self.count)
        # if self.count == 0:
        #     pass
        # else:
        self._socket_recv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        if size is not None:
            return self._socket_recv.recv(size)
        else:
            self._socket_recv.setblocking(0)
            timeout = 5
            start_time = time.time()
            ret = b""
            try:
                while True:
                    if len(ret) > 0 or time.time() - start_time > timeout:
                        break
                    try:
                        recv_packet = self._socket_recv.recv(4096)
                        """
                        logger.info(recv_packet)
                        """
                        byte_18 = recv_packet[17]
                        protocol_id = byte_18
                        byte_54 = recv_packet[53]
                        neighbor = byte_54
                        
                        if protocol_id == 0x83 and neighbor == 0x06:
                            ret += recv_packet
                    
                        # ret += recv_packet
                    except BlockingIOError as e:
                        pass
                    except socket.error as e:
                        if (
                                str(e).find(
                                    "The socket operation could not complete without blocking"
                                )
                                == -1
                        ):
                            raise
            except:
                logger.error(traceback.format_exc())
            finally:
                self._socket_recv.setblocking(1)
            self.count += 1
            self._socket_recv = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            print(ret,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
            return ret



            
                          
