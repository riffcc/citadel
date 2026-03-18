//! Content models for Lens.
//!
//! Defines the core data types for content in the distributed network.
//!
//! # Core Types
//!
//! - [`Release`] - Legacy model for albums, movies, TV series, etc.
//! - [`ContentItem`] - Universal content item supporting all content types
//! - [`Category`] - Content categorization
//! - [`FeaturedRelease`] - Promotional featured content entries
//!
//! # Supporting Types
//!
//! - [`ContentType`] - Discriminator for 50+ content types
//! - [`Creator`] - Creator with role and optional identifier
//! - [`CreatorRole`] - Role enum (Author, Artist, Director, etc.)
//! - [`License`] - License information with SPDX support
//! - [`Resource`] - File/resource reference
//!
//! # Metadata
//!
//! - [`MetadataContainer`] - Container for multiple metadata standards
//! - [`StandardMetadata`] - Dublin Core, Schema.org, DataCite, etc.

mod category;
mod content_item;
mod content_types;
mod featured_release;
mod metadata;
mod release;
mod site;

pub use category::Category;
pub use content_item::ContentItem;
pub use content_types::{ContentType, Creator, CreatorRole, License, Resource};
pub use featured_release::FeaturedRelease;
pub use metadata::{
    DataCiteCreator, DataCiteResourceType, DataCiteTitle, MetadataContainer, NameIdentifier,
    StandardMetadata,
};
pub use release::{Release, ReleaseStatus};
pub use site::{RendererMode, SiteManifest};
