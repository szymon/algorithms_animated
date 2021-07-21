import struct
import curses
import time


def left_rotate(n, b, size=32):
    return ((n << b) | (n >> (size - b))) & ((1 << size) - 1)


BAR = "================"
DEBUG = 0


def pad_hex(number):
    max_int32 = (1 << 32) - 1
    max_hex_len = len(hex(max_int32)[2:])
    hex_num = hex(number)[2:]

    padded_hex = "0" * (max_hex_len - len(hex_num)) + hex_num
    return padded_hex


def pad_bin(number):
    max_int32 = (1 << 32) - 1
    max_bin_len = len(bin(max_int32)[2:])
    bin_num = bin(number)[2:]

    padded_bin = "0" * (max_bin_len - len(bin_num)) + bin_num
    return padded_bin


def sleep(stdscr, sec):
    if DEBUG:
        return
    stdscr.refresh()
    time.sleep(sec)


def show_header(stdscr: "curses._CursesWindow", data: bytes):
    stdscr.addstr(0, 0, BAR)
    stdscr.addstr(1, 0, f" Size in bytes:     {len(data)}")
    stdscr.addstr(2, 0, " Message:")

    y = 2
    for i in range(0, len(data), 16):
        parts = [data[i : i + 16][j : j + 2] for j in range(0, 32, 2)]

        x = 20
        for p in parts:
            stdscr.addstr(y, x, p.hex())
            x += 5

            sleep(stdscr, 0.002)

        y += 1

    stdscr.addstr(y, 0, BAR)

    return y + 1


def show_h(stdscr: "curses._CursesWindow", y, h0, h1, h2, h3, h4):
    hvals = (h0, h1, h2, h3, h4)

    for i, h in enumerate(hvals):
        show_int(stdscr, y, 0, f"h[{i}]", h)
        y += 1

    stdscr.addstr(y, 0, BAR)

    return y + 1


class ShowMode:
    HEX = 1
    BIN = 2


def show_buffer(
    stdscr: "curses._CursesWindow", y, x, name, buffer, sec=0.002, show_mode=ShowMode.HEX
):
    if show_mode == ShowMode.BIN:
        return show_buffer_bin(stdscr, y, x, name, buffer, sec=sec)

    elif show_mode == ShowMode.HEX:
        return show_buffer_hex(stdscr, y, x, name, buffer, sec=sec)


def show_buffer_bin(stdscr: "curses._CursesWindow", y, x, name, buffer, sec=0.002):

    stdscr.addstr(y, x, f" {name} = {buffer.hex()}")


def show_int(stdscr: "curses._CursesWindow", y, x, name, number):
    padded_bin = pad_bin(number)
    padded_hex = pad_hex(number)

    stdscr.addstr(y, x, f" {name} = 0b{padded_bin} (0x{padded_hex})")


def show_buffer_hex(stdscr: "curses._CursesWindow", y, x, name, buffer, sec=0.002):

    header = f" {name} = "
    stdscr.addstr(y, x, header)
    size = 32
    x += len(header)

    for i in range(0, len(buffer), size):
        part = buffer[i : i + size]

        stdscr.addstr(y, x, part.hex())

        sleep(stdscr, sec)

        y += 1

    return y


def sha1(stdscr: "curses._CursesWindow", data: bytes) -> bytes:
    stdscr.clear()
    curses.curs_set(0)
    curses.noecho()

    y = show_header(stdscr, data)

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    y = show_h(stdscr, y, h0, h1, h2, h3, h4)

    ml = len(data) * 8

    # preprocessing

    buffer = bytearray(data)

    sleep(stdscr, 0.1)
    stdscr.addstr(y, 0, f" ml = {ml}")
    show_buffer(stdscr, y + 1, 0, "buffer", buffer, sec=0.01)

    buffer.extend(b"\x80")
    while (len(buffer) * 8) % 512 != 448:
        buffer.extend(b"\x00")

        show_buffer(stdscr, y + 1, 0, "buffer", buffer, sec=0.02)

    buffer.extend(struct.pack(">Q", ml))
    show_buffer(stdscr, y + 1, 0, "buffer", buffer)
    sleep(stdscr, 0.5)

    assert (len(buffer) * 8) % 512 == 0

    chunks = [buffer[i : i + 64] for i in range(0, len(buffer), 64)]

    y = 0
    stdscr.clear()
    y = show_buffer(stdscr, y, 0, "buffer", buffer, 0.1)
    y += 2

    for i, chunk in enumerate(chunks):
        y = show_buffer(stdscr, y, 2, f"chunks[{i}]", chunk, sec=0.1)
        sleep(stdscr, 0.01)
        y += 1

    for j, chunk in enumerate(chunks):
        w = list(struct.unpack(">16L", chunk)) + [0] * 64

        stdscr.clear()
        y = show_buffer(stdscr, 1, 2, f"chunks[{j}]", chunk, sec=0.1)
        y += 1
        x = 6

        for i in range(16, 80):
            xor = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            w[i] = left_rotate(xor, 1)

            # fmt: off
            show_int(stdscr, y + 0, x, f"w[{i - 16:<2}]", w[i - 16]); sleep(stdscr, 0.005)
            show_int(stdscr, y + 1, x, f"w[{i - 14:<2}]", w[i - 14]); sleep(stdscr, 0.005)
            show_int(stdscr, y + 2, x, f"w[{i -  8:<2}]", w[i -  8]); sleep(stdscr, 0.005)
            show_int(stdscr, y + 3, x, f"w[{i -  3:<2}]", w[i -  3]); sleep(stdscr, 0.005)

            show_int(stdscr, y + 4, x + 2, "XOR", xor); sleep(stdscr, 0.005)
            show_int(stdscr, y + 5, x, f"w[{i}]", w[i]); sleep(stdscr, 0.005)
            # fmt: on

            sleep(stdscr, 0.07)

        a, b, c, d, e = h0, h1, h2, h3, h4
        stdscr.clear()
        y = show_buffer(stdscr, 1, 2, f"chunks[{j}]", chunk, sec=0.1)

        stdscr.addstr(y + 1, 0, BAR)
        y = show_h(stdscr, y + 2, h0, h1, h2, h3, h4)
        y += 1

        for i in range(80):
            if i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            show_int(stdscr, y + 1, x, f"w[{i:<2}]", w[i])

            def show_variables(offset):
                show_int(stdscr, offset + 0, x, "    f", f)
                show_int(stdscr, offset + 1, x, "    k", k)
                show_int(stdscr, offset + 2, x, "    a", a)
                show_int(stdscr, offset + 3, x, "    b", b)
                show_int(stdscr, offset + 4, x, "    c", c)
                show_int(stdscr, offset + 5, x, "    d", d)
                show_int(stdscr, offset + 6, x, "    e", e)

            show_variables(y + 2)

            sleep(stdscr, 0.1)

            temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    stdscr.clear()
    stdscr.refresh()

    stdscr.addstr(1, 0, BAR)
    y = show_h(stdscr, 2, h0, h1, h2, h3, h4)

    y += 2
    x = 3

    stdscr.addstr(y - 1, 0, "         h0       h1       h2       h3       h4")
    stdscr.addstr(y, x + 0, pad_hex(h0))
    stdscr.addstr(y, x + 9, pad_hex(h1))
    stdscr.addstr(y, x + 18, pad_hex(h2))
    stdscr.addstr(y, x + 27, pad_hex(h3))
    stdscr.addstr(y, x + 36, pad_hex(h4))

    hh = left_rotate(h0, 128, 160)
    hh |= left_rotate(h1, 96, 160)
    hh |= left_rotate(h2, 64, 160)
    hh |= left_rotate(h3, 32, 160)
    hh |= h4

    stdscr.refresh()
    stdscr.getkey()

    return struct.pack(">5L", h0, h1, h2, h3, h4)
