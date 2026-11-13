import time

from attacker_common import run_profile, select_profile


def main():
    time.sleep(2)
    profile = select_profile("human")
    run_profile(profile, "human")
    time.sleep(4)


if __name__ == "__main__":
    main()
