package provide azure 1.0

#
# A custom theme for Tkinter's themed widgets (ttk),
# which is inspired by modern flat design.
#
# Author: rdbende
# Publisher: Github
#
# Just place this file in the same directory as your script,
# and use it with the following code:
#   root.tk.call("source", "azure.tcl")
#   root.tk.call("set_theme", "dark")
#
# For more information, please check out the repository:
#   https://github.com/rdbende/Azure-tcl-theme
#

package require Tk 8.6

namespace eval ttk::theme::azure {
    variable colors
    array set colors {
        border      "#323232"
        bg          "#464646"

        lightest-fg "#ffffff"
        lighter-fg  "#f5f5f5"
        fg          "#e8e8e8"

        darkest-fg  "#000000"
        darker-fg   "#121212"
        dark-fg     "#232323"

        accent      "#007fff"
        second-fg   "#878787"
        second-bg   "#3f3f3f"

        danger      "#dc3545"
        success     "#28a745"
        warning     "#ffc107"
        info        "#17a2b8"
    }
}

proc ttk::theme::azure::patch_proc {name args} {
    if {[catch {
        rename ::$name ::${name}_orig
        proc ::$name {w args} "
            if {\[string match ttk::treeview \$w\] && \[string match columns \[lindex \$args 0\]\]} {
                return \[eval ttk::theme::azure::patch_proc ${name}_orig \$w \$args\]
            }
            return \[eval ${name}_orig \$w \$args\]
        "
    }]} {
        # already patched
    }
}

proc ttk::theme::azure::load_theme {type} {
    variable colors
    switch -- $type {
        "light" {
            array set colors {
                border      "#adadad"
                bg          "#ffffff"

                lightest-fg "#000000"
                lighter-fg  "#121212"
                fg          "#232323"

                darkest-fg  "#ffffff"
                darker-fg   "#f5f5f5"
                dark-fg     "#e8e8e8"

                accent      "#007fff"
                second-fg   "#878787"
                second-bg   "#fafafa"

                danger      "#dc3545"
                success     "#28a745"
                warning     "#ffc107"
                info        "#17a2b8"
            }
        }
        "dark" {
            array set colors {
                border      "#323232"
                bg          "#464646"

                lightest-fg "#ffffff"
                lighter-fg  "#f5f5f5"
                fg          "#e8e8e8"

                darkest-fg  "#000000"
                darker-fg   "#121212"
                dark-fg     "#232323"

                accent      "#007fff"
                second-fg   "#878787"
                second-bg   "#3f3f3f"

                danger      "#dc3545"
                success     "#28a745"
                warning     "#ffc107"
                info        "#17a2b8"
            }
        }
    }

    ttk::style theme create azure -parent clam -settings {

        # Default settings
        ttk::style configure . \
            -background $colors(bg) \
            -foreground $colors(fg) \
            -bordercolor $colors(border) \
            -troughcolor $colors(bg) \
            -selectbackground $colors(accent) \
            -selectforeground $colors(lightest-fg) \
            -fieldbackground $colors(second-bg) \
            -font {Segoe UI} 9

        ttk::style map . \
            -background [list disabled $colors(second-bg) readonly $colors(second-bg)] \
            -foreground [list disabled $colors(second-fg)] \
            -bordercolor [list disabled $colors(border) readonly $colors(border)] \
            -fieldbackground [list disabled $colors(second-bg) readonly $colors(second-bg)]

        # Button
        ttk::style configure TButton \
            -padding {10 5} \
            -anchor center \
            -relief raised \
            -focusthickness 0
        ttk::style map TButton \
            -background [list pressed $colors(accent) active $colors(second-bg)]

        # Accent button
        ttk::style configure Accent.TButton \
            -background $colors(accent) \
            -foreground $colors(lightest-fg)
        ttk::style map Accent.TButton \
            -background [list pressed $colors(accent) active $colors(accent)] \
            -foreground [list pressed $colors(lightest-fg)]

        # Checkbutton
        ttk::style configure TCheckbutton -indicatordiameter 15
        ttk::style map TCheckbutton \
            -indicatorbackground [list selected $colors(accent) pressed $colors(accent) active $colors(second-bg)] \
            -indicatorforeground [list selected $colors(lightest-fg) pressed $colors(lightest-fg)]

        # Combobox
        ttk::style configure TCombobox \
            -arrowsize 15 \
            -padding {5 5 0 5}
        ttk::style map TCombobox \
            -background [list readonly $colors(second-bg)] \
            -fieldbackground [list readonly $colors(second-bg)] \
            -foreground [list readonly $colors(fg)]

        # Entry
        ttk::style configure TEntry -padding 10

        # Frame
        ttk::style configure TFrame -background $colors(bg)

        # Label
        ttk::style configure TLabel -padding 5

        # Menubutton
        ttk::style configure TMenubutton -padding 10

        # Notebook
        ttk::style layout TNotebook.Tab {
            Notebook.tab -children {
                Notebook.padding -side top -children {
                    Notebook.focus -side top -children {
                        Notebook.label -side top -text "Tab"
                    }
                }
            }
        }
        ttk::style configure TNotebook.Tab \
            -padding {10 5} \
            -background $colors(bg)
        ttk::style map TNotebook.Tab \
            -background [list selected $colors(bg) active $colors(second-bg)] \
            -bordercolor [list selected $colors(accent)] \
            -padding [list selected {10 7 10 5}]

        # Panedwindow
        ttk::style configure TPanedwindow -sashwidth 2 -sashrelief solid -sashpad 0

        # Progressbar
        ttk::style configure TProgressbar \
            -background $colors(accent) \
            -troughcolor $colors(second-bg)

        # Radiobutton
        ttk::style configure TRadiobutton -indicatordiameter 15
        ttk::style map TRadiobutton \
            -indicatorbackground [list selected $colors(accent) pressed $colors(accent) active $colors(second-bg)] \
            -indicatorforeground [list selected $colors(lightest-fg) pressed $colors(lightest-fg)]

        # Scale
        ttk::style configure TScale -gripcount 0
        ttk::style map TScale \
            -sliderbackground [list pressed $colors(accent) active $colors(accent)] \
            -background [list active $colors(second-bg)]

        # Scrollbar
        ttk::style configure TScrollbar \
            -arrowsize 15 \
            -relief solid \
            -borderwidth 0 \
            -padding 2
        ttk::style map TScrollbar \
            -background [list active $colors(second-bg)] \
            -troughcolor [list active $colors(bg)] \
            -arrowcolor [list active $colors(fg)]

        # Separator
        ttk::style configure TSeparator -background $colors(border)

        # Treeview
        ttk::style element create Treeview.Heading border \
            image [listclam-defaults-border] {
                border 2
                sticky nswe
            }
        ttk::style layout Treeview.Heading {
            Treeview.Heading.border -children {
                Treeview.padding -expand 1 -sticky ew -children {
                    Treeview.text -sticky ew
                }
            }
        }
        ttk::style configure Treeview \
            -rowheight 25 \
            -fieldbackground $colors(second-bg)
        ttk::style configure Treeview.Heading \
            -background $colors(second-bg) \
            -foreground $colors(fg) \
            -relief solid

        # Sizegrip
        ttk::style configure TSizegrip -background $colors(bg)
    }
}

proc ttk::theme::azure::set_theme {type} {
    # This proc will be removed after Tk 8.7 is released
    # and the code inside is moved to the ::ttk::set_theme proc.
    # Until then, it is better not to touch it!

    switch -- $type {
        "light" { ttk::theme::azure::load_theme light }
        "dark" { ttk::theme::azure::load_theme dark }
    }
}

# This proc will be removed after Tk 8.7 is released
# and the code inside is moved to the ::ttk::set_theme proc.
# Until then, it is better not to touch it!
proc ttk::theme::azure::set_theme {type} {
    switch -- $type {
        "light" { ttk::theme::azure::load_theme light }
        "dark" { ttk::theme::azure::load_theme dark }
    }
}

if {[llength [info commands ::ttk::set_theme_orig]] == 0} {
    rename ::ttk::set_theme ::ttk::set_theme_orig
    proc ::ttk::set_theme {name} {
        # This proc will be removed, as mentioned above.

        if {[string match "azure*" $name]} {
            switch -- $name {
                "azure-light" {
                    ttk::theme::azure::set_theme light
                }
                "azure-dark" {
                    ttk::theme::azure::set_theme dark
                }
                "azure" {
                    expr {[tk windowingsystem] eq "aqua" ? (
                        ttk::theme::azure::set_theme light
                    ) : (
                        ttk::style theme use "azure"
                    )}
                }
            }
        } else {
            ::ttk::set_theme_orig $name
        }
    }
}


ttk::theme::azure::load_theme dark

# The following two lines were provided by the OP on Github in his fix,
# and they fix the sorting arrow color on MacOS and Windows. It works...
ttk::theme::azure::patch_proc ttk::treeview::heading
ttk::theme::azure::patch_proc ttk::treeview::column

ttk::style theme use azure