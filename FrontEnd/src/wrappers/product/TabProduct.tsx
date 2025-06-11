import PropTypes from "prop-types";
import React from "react";
import Tab from "react-bootstrap/Tab";
import Nav from "react-bootstrap/Nav";
import SectionTitle from "../../components/section-title/SectionTitle";
import ProductGrid from "./ProductGrid";

const TabProduct = ({spaceTopClass, spaceBottomClass, bgColorClass}: any) => {
    return (
        <div
            className={`product-area ${spaceTopClass ? spaceTopClass : ""} ${spaceBottomClass ? spaceBottomClass : ""} ${bgColorClass ? bgColorClass : ""}`}>
            <div className="container">
                <SectionTitle titleText="CÁC SẢN PHẨM" positionClass="text-center"/>
                <Tab.Container defaultActiveKey={"newArrival"}>
                    <Nav
                        variant="pills"
                        className="product-tab-list pt-30 pb-55 text-center"
                    >
                        <Nav.Item>
                            <Nav.Link eventKey="newArrival">
                                <h4>Sản phẩm mới</h4>
                            </Nav.Link>
                        </Nav.Item>
                        <Nav.Item>
                            <Nav.Link eventKey="saleItems">
                                <h4>Giảm giá</h4>
                            </Nav.Link>
                        </Nav.Item>
                    </Nav>
                    <Tab.Content>
                        <Tab.Pane eventKey="newArrival">
                            <div className="row">
                                <ProductGrid
                                    type="new"
                                    limit={8}
                                    spaceBottomClass="mb-25"
                                />
                            </div>
                        </Tab.Pane>
                        <Tab.Pane eventKey="saleItems">
                            <div className="row">
                                <ProductGrid
                                    type="saleItems"
                                    limit={8}
                                    spaceBottomClass="mb-25"
                                />
                            </div>
                        </Tab.Pane>
                    </Tab.Content>
                </Tab.Container>
            </div>
        </div>
    );
};

TabProduct.propTypes = {
    bgColorClass: PropTypes.string,
    category: PropTypes.string,
    spaceBottomClass: PropTypes.string,
    spaceTopClass: PropTypes.string
};

export default TabProduct;
