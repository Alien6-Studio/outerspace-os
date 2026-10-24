# OuterSpace identity

The vector mark keeps the original faceted mountain/spacecraft silhouette and
blue, violet and rose palette, with an orbital ring. `outerspace-mark.svg` is the
editable source and can be used for the website favicon and distribution assets.
The original planetary illustration is retained on the website.

The boot banner is plain ASCII in
`src/image/mkosi.extra/usr/share/outerspace/banner.txt`. The boot service displays the
actual image version and a development label; it does not pretend a prerelease is
stable. The named `outerspace` operator account starts password-locked, has a
persistent private home and has no sudo privileges. Root remains locked.

An administrative access profile needs explicit authentication provisioning,
auditing and CIS tailoring. No shared password, passwordless super-admin account
or automatic console login is included in the base image.
