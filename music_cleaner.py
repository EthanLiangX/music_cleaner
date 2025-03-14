#!/usr/bin/env python3
"""
极空间NAS音乐去重终极版 (v1.2)
功能：音频指纹校验 + 智能元数据匹配 + 安全处理
"""

import os
import sys
import hashlib
import argparse
import logging
import json
from collections import defaultdict
from functools import lru_cache
import audioread
import mutagen
from mutagen import MutagenError
from pydub import AudioSegment
from pydub.exceptions import CouldntDecodeError

# ------------------- 配置部分 -------------------
LOG_FORMAT = '[%(levelname)s] %(asctime)s - %(message)s'
SUPPORTED_FORMATS = ('.mp3', '.flac', '.wav', '.m4a', '.ape')
PRIORITY_FORMATS = ['.flac', '.wav', '.ape', '.m4a', '.mp3']
MIN_BITRATE = 128  # 最低保留比特率 (kbps)

# ------------------- 初始化日志 -------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(handler)


# ------------------- 工具函数 -------------------
def sanitize_path(path):
    """安全路径校验"""
    if not os.path.abspath(path).startswith('/music'):
        raise ValueError("非法路径访问")
    if '../' in path:
        raise ValueError("路径包含非法字符")
    return os.path.abspath(path)


def get_audio_hash(filepath):
    """生成抗转码哈希 (跳过前30秒)"""
    hash_sha256 = hashlib.sha256()
    try:
        with audioread.audio_open(filepath) as f:
            # 稳健化位深度处理
            bits_per_sample = 16  # 默认CD音质

            # 尝试不同方法获取位深度
            try:
                # 标准属性获取
                bits_per_sample = f.bit_depth
            except AttributeError:
                # 尝试通过元数据获取
                try:
                    audio = mutagen.File(filepath)
                    if audio and hasattr(audio.info, 'bits_per_sample'):
                        bits_per_sample = audio.info.bits_per_sample
                except Exception as meta_error:
                    logger.debug(f"元数据获取位深度失败: {filepath} - 使用默认16bit")

            # 计算跳过的字节数
            bytes_per_second = f.samplerate * f.channels * (bits_per_sample // 8)
            skip_bytes = 30 * bytes_per_second  # 跳过30秒

            # 缓冲读取处理
            bytes_read = 0
            buffer = bytearray()
            for buf in f:
                buffer.extend(buf)
                while len(buffer) >= 4096:  # 使用固定块处理
                    chunk = buffer[:4096]
                    del buffer[:4096]

                    if bytes_read < skip_bytes:
                        remain = skip_bytes - bytes_read
                        if len(chunk) > remain:
                            chunk = chunk[remain:]
                            bytes_read += remain
                        else:
                            bytes_read += len(chunk)
                            continue
                    hash_sha256.update(chunk)

            # 处理剩余缓冲
            if buffer:
                hash_sha256.update(buffer)

        return hash_sha256.hexdigest()
    except Exception as e:
        logger.warning(f"哈希生成失败: {filepath} - {str(e)}")
        return None


@lru_cache(maxsize=500)
def get_metadata(filepath):
    """带缓存的元数据读取"""
    try:
        audio = mutagen.File(filepath, easy=True)
        if audio is None:
            return None

        return {
            'artist': audio.get('artist', ['未知'])[0].strip().lower(),
            'title': audio.get('title', ['未知'])[0].strip().lower(),
            'duration': int(audio.info.length),
            'bitrate': getattr(audio.info, 'bitrate', 0) // 1000,
            'format': os.path.splitext(filepath)[1].lower(),
            'channels': getattr(audio.info, 'channels', 2)
        }
    except MutagenError as e:
        logger.debug(f"元数据错误: {filepath} - {str(e)}")
        return None


def select_best_file(candidates):
    """智能选择最佳文件"""

    def sort_key(x):
        try:
            fmt_priority = PRIORITY_FORMATS.index(x['format'])
        except ValueError:
            fmt_priority = 999

        return (
            -fmt_priority,  # 格式优先级降序
            -x['bitrate'],  # 比特率降序
            x['channels'],  # 声道数降序
            -len(x['path']),  # 路径长度升序
            x['path']  # 字典序
        )

    return max(candidates, key=sort_key)


# ------------------- 核心逻辑 -------------------
class MusicDeduplicator:
    def __init__(self, root_dir, dry_run=True, min_bitrate=128):
        self.root_dir = sanitize_path(root_dir)
        self.dry_run = dry_run
        self.min_bitrate = min_bitrate
        self.stats = {
            'total_files': 0,
            'duplicates': 0,
            'deleted': 0,
            'errors': 0
        }

        # 初始化索引
        self.hash_groups = defaultdict(list)
        self.meta_groups = defaultdict(list)

    def scan(self):
        """扫描目录建立索引"""
        for root, _, files in os.walk(self.root_dir):
            for fname in files:
                filepath = os.path.join(root, fname)
                self.stats['total_files'] += 1

                if not fname.lower().endswith(SUPPORTED_FORMATS):
                    continue

                try:
                    # 获取哈希和元数据
                    audio_hash = get_audio_hash(filepath)
                    meta = get_metadata(filepath)

                    if not audio_hash or not meta:
                        self.stats['errors'] += 1
                        continue

                    # 过滤低质量文件
                    if meta['bitrate'] < self.min_bitrate:
                        logger.info(f"跳过低比特率文件 ({meta['bitrate']}kbps): {fname}")
                        continue

                    # 记录到索引
                    entry = {'path': filepath, **meta}
                    self.hash_groups[audio_hash].append(entry)
                    meta_key = f"{meta['artist']}||{meta['title']}"
                    self.meta_groups[meta_key].append(entry)

                except Exception as e:
                    logger.error(f"处理失败: {filepath} - {str(e)}")
                    self.stats['errors'] += 1

    def deduplicate(self):
        """执行去重操作"""
        # 合并重复组
        all_groups = []
        for group in self.hash_groups.values():
            if len(group) > 1:
                all_groups.append(group)

        for group in self.meta_groups.values():
            if len(group) > 1 and not any(
                    item in sum(all_groups, []) for item in group
            ):

                all_groups.append(group)
        # 处理每个重复组
        for group in all_groups:
            self.stats['duplicates'] += len(group) - 1
            best = select_best_file(group)

            logger.info(f"\n► 发现 {len(group)} 个重复项")
            logger.info(f"   保留: {best['path']}")
            logger.info(f"   格式: {best['format']}, 比特率: {best['bitrate']}kbps")

            for item in group:
                if item['path'] == best['path']:
                    continue

                try:
                    if self.dry_run:
                        logger.info(f"   [模拟] 删除: {item['path']}")
                    else:
                        os.remove(item['path'])
                        logger.info(f"   已删除: {item['path']}")
                        self.stats['deleted'] += 1
                except Exception as e:
                    logger.error(f"   操作失败: {item['path']} - {str(e)}")
                    self.stats['errors'] += 1

        # 生成报告
        report = {
            'scanned': self.stats['total_files'],
            'duplicates_found': self.stats['duplicates'],
            'deleted': self.stats['deleted'],
            'errors': self.stats['errors'],
            'remaining': self.stats['total_files'] - self.stats['deleted']
        }
        return report


# ------------------- CLI入口 -------------------
def main():
    parser = argparse.ArgumentParser(
        description='极空间NAS音乐库去重工具',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('path', help='音乐库根目录')
    parser.add_argument('--dry-run', action='store_true',
                        help='试运行模式（不实际删除）')
    parser.add_argument('--min-bitrate', type=int, default=MIN_BITRATE,
                        help='最低保留比特率 (kbps)')
    parser.add_argument('--log-file', help='日志文件路径')
    args = parser.parse_args()

    try:
        # 初始化去重器
        dedup = MusicDeduplicator(
            root_dir=args.path,
            dry_run=args.dry_run,
            min_bitrate=args.min_bitrate
        )

        logger.info("开始扫描音乐库...")
        dedup.scan()

        logger.info("分析重复项...")
        report = dedup.deduplicate()

        # 打印报告
        logger.info("\n=== 去重报告 ===")
        logger.info(f"扫描文件总数: {report['scanned']}")
        logger.info(f"发现重复项: {report['duplicates_found']}")
        logger.info(f"已删除文件: {report['deleted']}")
        logger.info(f"剩余文件: {report['remaining']}")
        logger.info(f"错误计数: {report['errors']}")

        # 保存报告
        if args.log_file:
            with open(args.log_file, 'w') as f:
                json.dump(report, f, indent=2)

        sys.exit(0 if report['errors'] == 0 else 1)

    except Exception as e:
        logger.critical(f"致命错误: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()