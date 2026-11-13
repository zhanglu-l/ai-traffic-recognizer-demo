from attacker_common import run_profile, select_profile


def main():
    profile = select_profile("ai")
    run_profile(profile, "ai")


if __name__ == "__main__":
    main()
