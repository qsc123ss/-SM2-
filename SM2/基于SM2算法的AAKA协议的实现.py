from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Math.Numbers import Integer
from Crypto.Protocol.KDF import scrypt


# 步骤 1: 系统初始化
def system_initialization():
    # 选择椭圆曲线 E 和基点 Fp（公共参数）
    curve = 'P-256'
    G = ECC.generate(curve=curve).pointQ  # G 是曲线上的基点

    # 服务器 B 生成私钥-公钥对 (dB, PB)
    server_B_key = ECC.generate(curve=curve)
    dB = server_B_key.d
    PB = server_B_key.pointQ

    return curve, G, dB, PB


# 步骤 2: 用户认证请求（匿名身份创建）
def user_authentication_request(curve, G, PB):
    # 用户 A 生成一个临时密钥对 (rA, PA)
    user_A_key = ECC.generate(curve=curve)
    rA = user_A_key.d
    PA = user_A_key.pointQ

    # 获取曲线的阶（order）
    curve_order = user_A_key._curve.order

    # 用户 A 选择随机数 kA 并计算会话密钥组件
    kA = Integer(int.from_bytes(get_random_bytes(32), 'big')) % curve_order
    C1 = kA * G
    SA = kA * PB

    # 生成身份验证消息 MA
    A_identity = b'User_A_identity'
    hash_obj = SHA256.new(A_identity)
    hash_obj.update(C1.xy[0].to_bytes() + C1.xy[1].to_bytes())
    H_SA = hash_obj.digest()

    return rA, PA, C1, SA, H_SA, A_identity, kA


# 步骤 3: 服务器 B 验证用户身份并生成随机数 kB
def server_verifies_identity_and_generate_kB(dB, PB, C1, SA, H_SA, A_identity):
    # 服务器 B 计算 SB = dB * C1
    SB = dB * C1

    # 服务器 B 计算接收到的身份的哈希值
    hash_obj = SHA256.new(A_identity)
    hash_obj.update(C1.xy[0].to_bytes() + C1.xy[1].to_bytes())
    H_SB = hash_obj.digest()

    # 比较 H_SA 和 H_SB
    if H_SA == H_SB:
        print("身份验证成功：用户 A 是合法的。")
        # 服务器 B 选择随机数 kB
        curve_order = PB._curve.order
        kB = Integer(int.from_bytes(get_random_bytes(32), 'big')) % curve_order
        return True, kB
    else:
        print("验证失败：身份不匹配。")
        return False, None


# 步骤 4: 密钥协商（共享密钥生成）
def key_agreement(rA, kA, kB, dB, PA, PB):
    # 服务器 B 计算共享密钥 SB = kB * PA
    SB = kB * PA

    # 服务器 B 计算会话密钥组件 C2 = kB * G
    G = ECC._curves[curve].G
    C2 = kB * G

    # 服务器 B 使用 KDF 函数生成共享密钥 K
    shared_salt = b'shared_salt'
    K_server = scrypt(SB.xy[0].to_bytes() + SB.xy[1].to_bytes() + C2.xy[0].to_bytes() + C2.xy[1].to_bytes(),
                      salt=shared_salt, key_len=32, N=2 ** 14, r=8, p=1)

    # 用户 A 计算共享密钥 SA = rA * C2
    SA = rA * C2

    # 用户 A 使用 KDF 函数生成共享密钥 K
    K_user = scrypt(SA.xy[0].to_bytes() + SA.xy[1].to_bytes() + C2.xy[0].to_bytes() + C2.xy[1].to_bytes(),
                    salt=shared_salt, key_len=32, N=2 ** 14, r=8, p=1)

    # 打印共享密钥
    print("服务器 B 生成的共享密钥 K:", K_server.hex())
    print("用户 A 生成的共享密钥 K:", K_user.hex())


if __name__ == '__main__':
    # 初始化系统
    curve, G, dB, PB = system_initialization()

    # 用户 A 发起认证请求
    rA, PA, C1, SA, H_SA, A_identity, kA = user_authentication_request(curve, G, PB)

    # 服务器 B 验证用户 A 的身份并生成随机数 kB
    valid, kB = server_verifies_identity_and_generate_kB(dB, PB, C1, SA, H_SA, A_identity)

    if valid:
        # 身份验证成功后，进行密钥协商
        key_agreement(rA, kA, kB, dB, PA, PB)
