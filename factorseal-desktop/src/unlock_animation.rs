//! The canonical mark and a brand-colored key. The animation is decorative:
//! runtime snapshots still determine when unlocking ends, including on failure.

use std::{f32::consts::PI, time::Duration};

use gpui::{
    Animation, AnimationExt as _, App, Bounds, ColorExt as _, Hsla, IntoElement, PathBuilder,
    Pixels, TransformationMatrix, Window, canvas, div, point, prelude::*, px, rems, size, svg,
};
use gpui_component::theme::Theme;

// Geometry of the canonical mark in assets/logo/factorseal-mark.svg. Align the
// insertion axis with the center of its round keyhole head.
const MARK_VIEWBOX_SIZE: f32 = 160.;
const KEYHOLE_CENTER_Y: f32 = 65.644;
const KEYHOLE_OFFSET_Y: f32 = KEYHOLE_CENTER_Y - MARK_VIEWBOX_SIZE / 2.;

/// Keep one logo slot in both states so the transition starts in place.
pub(crate) fn vault_mark(theme: &Theme, unlocking: bool) -> impl IntoElement {
    let ink = theme.foreground;
    let slot = div()
        .w(rems(260. / 16.))
        .h(rems(104. / 16.))
        .flex_shrink_0();
    if !unlocking {
        return slot
            .flex()
            .items_center()
            .justify_center()
            .child(
                svg()
                    .path(crate::branding::MARK_ASSET)
                    .size(rems(72. / 16.))
                    .text_color(ink),
            )
            .into_any_element();
    }
    slot.with_animation(
        "unlock-logo-intro",
        Animation::new(Duration::from_millis(450)).with_max_fps(30.),
        move |element, intro| {
            element.child(
                div().size_full().with_animation(
                    "unlock-key",
                    Animation::new(Duration::from_secs(3))
                        .repeat()
                        .with_max_fps(30.),
                    move |element, phase| {
                        element.child(
                            canvas(
                                |_, _, _| (),
                                move |bounds, (), window, cx| {
                                    paint(bounds, smooth(intro, 0., 1.), phase, ink, window, cx);
                                },
                            )
                            .size_full(),
                        )
                    },
                ),
            )
        },
    )
    .into_any_element()
}

#[derive(Clone, Copy)]
struct Vertex {
    x: f32,
    y: f32,
    z: f32,
}

impl Vertex {
    const fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }

    fn turn(self, angle: f32) -> Self {
        let (sin, cos) = angle.sin_cos();
        Self::new(
            self.x * cos - self.y * sin,
            self.x * sin + self.y * cos,
            self.z,
        )
    }

    fn depth(self) -> f32 {
        self.x * 0.8 - self.y * 0.24 + self.z
    }
}

struct Face {
    vertices: Vec<Vertex>,
    color: Hsla,
}

impl Face {
    /// A fixed upper-left light shades the key's edges, leaving its faces in Ink/Paper.
    fn new(vertices: Vec<Vertex>, mut color: Hsla) -> Self {
        let edge = |a: Vertex, b: Vertex| Vertex::new(b.x - a.x, b.y - a.y, b.z - a.z);
        let first = edge(vertices[0], vertices[1]);
        let second = edge(vertices[0], vertices[2]);
        let normal = Vertex::new(
            first.y * second.z - first.z * second.y,
            first.z * second.x - first.x * second.z,
            first.x * second.y - first.y * second.x,
        );
        let length = (normal.x * normal.x + normal.y * normal.y + normal.z * normal.z).sqrt();
        // Orient the normal toward the camera, independent of outline winding.
        let light = (-0.4 * normal.x - 0.65 * normal.y + 0.65 * normal.z) * normal.depth().signum()
            / length.max(0.001);
        let shading = 0.08 + 0.10 * (1. - light.clamp(-1., 1.));
        color.lightness = (color.lightness
            + if color.lightness > 0.5 {
                -shading
            } else {
                shading
            })
        .clamp(0., 1.);
        Self { vertices, color }
    }
}

fn solid(faces: &mut Vec<Face>, front: &[Vertex], back: &[Vertex], color: Hsla) {
    faces.push(Face {
        vertices: back.to_vec(),
        color,
    });
    for index in 0..front.len() {
        let next = (index + 1) % front.len();
        faces.push(Face::new(
            vec![front[index], back[index], back[next], front[next]],
            color,
        ));
    }
    faces.push(Face {
        vertices: front.to_vec(),
        color,
    });
}

fn smooth(phase: f32, start: f32, end: f32) -> f32 {
    let progress = ((phase - start) / (end - start)).clamp(0., 1.);
    progress * progress * (3. - 2. * progress)
}

/// A substantial square bow echoes the chip's subtly rounded body.
fn bow_point(step: u16, half_width: f32, half_height: f32, radius: f32) -> (f32, f32) {
    let corner = (step / 8) % 4;
    let angle = -PI / 2. + f32::from(corner) * PI / 2. + f32::from(step % 8) * PI / 16.;
    let x = if corner < 2 {
        half_width - radius
    } else {
        radius - half_width
    };
    let z = if corner == 0 || corner == 3 {
        radius - half_height
    } else {
        half_height - radius
    };
    (x + radius * angle.cos(), 128. + z + radius * angle.sin())
}

fn key(faces: &mut Vec<Face>, phase: f32, ink: Hsla) {
    // Insert without rotation, pause fully seated, then turn. Straighten again
    // before withdrawing so the next loop follows the same horizontal axis.
    let insertion = smooth(phase, 0.18, 0.44) - smooth(phase, 0.90, 0.99);
    let turn = (smooth(phase, 0.54, 0.69) - smooth(phase, 0.79, 0.87)) * PI * 0.5;
    let tip = 54. - insertion * 112.;
    // Clip the blade at the keyhole so it disappears into the logo.
    let mut key_plate = |outline: &[(f32, f32)]| {
        let layer = |y| {
            outline
                .iter()
                .map(|&(x, z)| Vertex::new(y, x, (z + tip).max(3.)).turn(turn))
                .collect::<Vec<_>>()
        };
        solid(faces, &layer(-3.5), &layer(3.5), ink);
    };
    key_plate(&[(-4.5, 0.), (4.5, 0.), (4.5, 103.), (-4.5, 103.)]);
    for z in [6., 20., 34.] {
        if tip + z + 8. > 3. {
            key_plate(&[(4.5, z), (14., z), (14., z + 8.), (4.5, z + 8.)]);
        }
    }
    for step in 0..32_u16 {
        key_plate(&[
            bow_point(step, 28., 32., 3.),
            bow_point(step + 1, 28., 32., 3.),
            bow_point(step + 1, 18., 22., 2.),
            bow_point(step, 18., 22., 2.),
        ]);
    }
}

/// Keep the canonical mark upright and uniformly scaled throughout the animation.
fn paint_logo(bounds: Bounds<Pixels>, reveal: f32, ink: Hsla, window: &mut Window, cx: &App) {
    let unit = bounds.size.width / px(260.);
    let scale = (72. - 20. * reveal) / MARK_VIEWBOX_SIZE * unit;
    let center = bounds.origin
        + point(
            bounds.size.width / 2. + px(20. * reveal * unit),
            bounds.size.height / 2.,
        );
    // A fixed raster size lets GPUI reuse the SVG atlas entry during the zoom.
    let source = Bounds::new(
        bounds.origin,
        size(px(MARK_VIEWBOX_SIZE), px(MARK_VIEWBOX_SIZE)),
    );
    let device_scale = window.scale_factor();
    let transform = TransformationMatrix::unit()
        .translate(center.scale(device_scale))
        .scale(size(scale, scale))
        .translate(source.center().scale(-device_scale));
    let _ = window.paint_svg(
        source,
        crate::branding::MARK_ASSET.into(),
        None,
        transform,
        ink,
        cx,
    );
}

fn paint(
    bounds: Bounds<Pixels>,
    reveal: f32,
    phase: f32,
    ink: Hsla,
    window: &mut Window,
    cx: &App,
) {
    paint_logo(bounds, reveal, ink, window, cx);
    let key_opacity = smooth(reveal, 0.8, 1.);
    if key_opacity == 0. {
        return;
    }
    let mut faces = Vec::with_capacity(320);
    key(&mut faces, phase, ink);

    let depth = |face: &Face| {
        face.vertices.iter().map(|v| v.depth()).sum::<f32>()
            / f32::from(u16::try_from(face.vertices.len()).unwrap_or(1))
    };
    faces.sort_by(|left, right| depth(left).total_cmp(&depth(right)));
    let unit = bounds.size.width / px(260.);
    let scale = (72. + 28. * reveal) / MARK_VIEWBOX_SIZE * unit;
    // Keep the key's size while following the smaller mark's keyhole center.
    let keyhole_y = KEYHOLE_OFFSET_Y * (72. - 20. * reveal) / MARK_VIEWBOX_SIZE * unit;
    for face in faces {
        // Depth moves only horizontally; a slight cross-sectional tilt keeps
        // the bow visible after the quarter-turn without angling the insertion.
        let project = |v: Vertex| {
            bounds.origin
                + point(
                    bounds.size.width / 2. + px(20. * reveal * unit + (v.x - v.z * 0.8) * scale),
                    bounds.size.height / 2. + px((v.y + v.x * 0.3) * scale + keyhole_y),
                )
        };
        let mut path = PathBuilder::fill();
        path.move_to(project(face.vertices[0]));
        for vertex in &face.vertices[1..] {
            path.line_to(project(*vertex));
        }
        path.close();
        if let Ok(path) = path.build() {
            window.paint_path(path, face.color.opacity(key_opacity));
        }
    }
}
